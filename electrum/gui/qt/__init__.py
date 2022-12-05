#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import signal
import sys
import traceback
import threading
from typing import Optional, TYPE_CHECKING, List

from electrum import GuiImportError

try:
    import PyQt5
    import PyQt5.QtGui
except Exception as e:
    raise GuiImportError(
        "Error: Could not import PyQt5 on Linux systems, "
        "you may try 'sudo apt-get install python3-pyqt5'") from e

from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import (QApplication, QSystemTrayIcon, QWidget, QMenu,
                             QMessageBox)
from PyQt5.QtCore import QObject, pyqtSignal, QTimer, Qt
import PyQt5.QtCore as QtCore

try:
    # Preload QtMultimedia at app start, if available.
    # We use QtMultimedia on some platforms for camera-handling, and
    # lazy-loading it later led to some crashes. Maybe due to bugs in PyQt5. (see #7725)
    from PyQt5.QtMultimedia import QCameraInfo; del QCameraInfo
except ImportError as e:
    pass  # failure is ok; it is an optional dependency.

from electrum.i18n import _, set_language
from electrum.plugin import run_hook
from electrum.base_wizard import GoBack
from electrum.util import (UserCancelled, profiler,
                           WalletFileException, BitcoinException, get_new_wallet_name)
from electrum.wallet import Wallet, Abstract_Wallet
from electrum.wallet_db import WalletDB
from electrum.logging import Logger
from electrum.gui import BaseElectrumGui

from .installwizard import InstallWizard, WalletAlreadyOpenInMemory
from .util import get_default_language, read_QIcon, ColorScheme, custom_message_box, MessageBoxMixin
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog
from .stylesheet_patcher import patch_qt_stylesheet
from .lightning_dialog import LightningDialog
from .watchtower_dialog import WatchtowerDialog

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        self.windows = windows
        super(OpenFileEventFilter, self).__init__()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toString())
                return True
        return False


class QElectrumApplication(QApplication):
    new_window_signal = pyqtSignal(str, object)
    quit_signal = pyqtSignal()
    refresh_tabs_signal = pyqtSignal()
    refresh_amount_edits_signal = pyqtSignal()
    update_status_signal = pyqtSignal()
    update_fiat_signal = pyqtSignal()
    alias_received_signal = pyqtSignal()


class QNetworkUpdatedSignalObject(QObject):
    network_updated_signal = pyqtSignal(str, object)


class ElectrumGui(BaseElectrumGui, Logger):

    network_dialog: Optional['NetworkDialog']
    lightning_dialog: Optional['LightningDialog']
    watchtower_dialog: Optional['WatchtowerDialog']

    @profiler
    def __init__(self, *, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        set_language(config.get('language', get_default_language()))
        BaseElectrumGui.__init__(self, config=config, daemon=daemon, plugins=plugins)
        Logger.__init__(self)
        self.logger.info(f"Qt GUI starting up... Qt={QtCore.QT_VERSION_STR}, PyQt={QtCore.PYQT_VERSION_STR}")
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum.desktop')
        self.gui_thread = threading.current_thread()
        self.windows = []  # type: List[ElectrumWindow]
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QElectrumApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.app.setWindowIcon(read_QIcon("electrum.png"))
        self._cleaned_up = False
        # timer
        self.timer = QTimer(self.app)
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec

        self.network_dialog = None
        self.lightning_dialog = None
        self.watchtower_dialog = None
        self.network_updated_signal_obj = QNetworkUpdatedSignalObject()
        self._num_wizards_in_progress = 0
        self._num_wizards_lock = threading.Lock()
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = None
        self._init_tray()
        self.app.new_window_signal.connect(self.start_new_window)
        self.app.quit_signal.connect(self.app.quit, Qt.QueuedConnection)
        # maybe set dark theme
        self._default_qtstylesheet = self.app.styleSheet()
        self.reload_app_stylesheet()

        run_hook('init_qt', self)

    def _init_tray(self):
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Electrum')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()

    def reload_app_stylesheet(self):
        """Set the Qt stylesheet and custom colors according to the user-selected
        light/dark theme.
        TODO this can ~almost be used to change the theme at runtime (without app restart),
             except for util.ColorScheme... widgets already created with colors set using
             ColorSchemeItem.as_stylesheet() and similar will not get recolored.
             See e.g.
             - in Coins tab, the color for "frozen" UTXOs, or
             - in TxDialog, the receiving/change address colors
        """
        use_dark_theme = self.config.get('qt_gui_color_theme', 'default') == 'dark'
        if use_dark_theme:
            try:
                import qdarkstyle
                self.app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
            except BaseException as e:
                use_dark_theme = False
                self.logger.warning(f'Error setting dark theme: {repr(e)}')
        else:
            self.app.setStyleSheet(self._default_qtstylesheet)
        # Apply any necessary stylesheet patches
        patch_qt_stylesheet(use_dark_theme=use_dark_theme)
        # Even if we ourselves don't set the dark theme,
        # the OS/window manager/etc might set *a dark theme*.
        # Hence, try to choose colors accordingly:
        ColorScheme.update_from_widget(QWidget(), force_dark=use_dark_theme)

    def build_tray_menu(self):
        if not self.tray:
            return
        # Avoid immediate GC of old menu when window closed via its action
        if self.tray.contextMenu() is None:
            m = QMenu()
            self.tray.setContextMenu(m)
        else:
            m = self.tray.contextMenu()
            m.clear()
        network = self.daemon.network
        m.addAction(_("Network"), self.show_network_dialog)
        if network and network.lngossip:
            m.addAction(_("Lightning Network"), self.show_lightning_dialog)
        if network and network.local_watchtower:
            m.addAction(_("Local Watchtower"), self.show_watchtower_dialog)
        for window in self.windows:
            name = window.wallet.basename()
            submenu = m.addMenu(name)
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            submenu.addAction(_("Close"), window.close)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electrum"), self.app.quit)

    def tray_icon(self):
        if self.dark_icon:
            return read_QIcon('electrum_dark_icon.png')
        else:
            return read_QIcon('electrum_light_icon.png')

    def toggle_tray_icon(self):
        if not self.tray:
            return
        self.dark_icon = not self.dark_icon
        self.config.set_key("dark_icon", self.dark_icon, True)
        self.tray.setIcon(self.tray_icon())

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if all([w.is_hidden() for w in self.windows]):
                for w in self.windows:
                    w.bring_to_top()
            else:
                for w in self.windows:
                    w.hide()

    def _cleanup_before_exit(self):
        if self._cleaned_up:
            return
        self._cleaned_up = True
        self.app.new_window_signal.disconnect()
        self.efilter = None
        # If there are still some open windows, try to clean them up.
        for window in list(self.windows):
            window.close()
            window.clean_up()
        if self.network_dialog:
            self.network_dialog.close()
            self.network_dialog.clean_up()
            self.network_dialog = None
        self.network_updated_signal_obj = None
        if self.lightning_dialog:
            self.lightning_dialog.close()
            self.lightning_dialog = None
        if self.watchtower_dialog:
            self.watchtower_dialog.close()
            self.watchtower_dialog = None
        # Shut down the timer cleanly
        self.timer.stop()
        self.timer = None
        # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)
        if self.tray:
            self.tray.hide()
            self.tray.deleteLater()
            self.tray = None

    def _maybe_quit_if_no_windows_open(self) -> None:
        """Check if there are any open windows and decide whether we should quit."""
        # keep daemon running after close
        if self.config.get('daemon'):
            return
        # check if a wizard is in progress
        with self._num_wizards_lock:
            if self._num_wizards_in_progress > 0 or len(self.windows) > 0:
                return
        self.app.quit()

    def new_window(self, path, uri=None):
        # Use a signal as can be called from daemon thread
        self.app.new_window_signal.emit(path, uri)

    def show_lightning_dialog(self):
        if not self.daemon.network.has_channel_db():
            return
        if not self.lightning_dialog:
            self.lightning_dialog = LightningDialog(self)
        self.lightning_dialog.bring_to_top()

    def show_watchtower_dialog(self):
        if not self.watchtower_dialog:
            self.watchtower_dialog = WatchtowerDialog(self)
        self.watchtower_dialog.bring_to_top()

    def show_network_dialog(self):
        if self.network_dialog:
            self.network_dialog.on_update()
            self.network_dialog.show()
            self.network_dialog.raise_()
            return
        self.network_dialog = NetworkDialog(
            network=self.daemon.network,
            config=self.config,
            network_updated_signal_obj=self.network_updated_signal_obj)
        self.network_dialog.show()

    def _create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        self.build_tray_menu()
        w.warn_if_testnet()
        w.warn_if_watching_only()
        return w

    def count_wizards_in_progress(func):
        def wrapper(self: 'ElectrumGui', *args, **kwargs):
            with self._num_wizards_lock:
                self._num_wizards_in_progress += 1
            try:
                return func(self, *args, **kwargs)
            finally:
                with self._num_wizards_lock:
                    self._num_wizards_in_progress -= 1
                self._maybe_quit_if_no_windows_open()
        return wrapper

    @count_wizards_in_progress
    def start_new_window(
            self,
            path,
            uri: Optional[str],
            *,
            app_is_starting: bool = False,
            force_wizard: bool = False,
    ) -> Optional[ElectrumWindow]:
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it'''
        wallet = None
        # Try to open with daemon first. If this succeeds, there won't be a wizard at all
        # (the wallet main window will appear directly).
        if not force_wizard:
            try:
                wallet = self.daemon.load_wallet(path, None)
            except Exception as e:
                self.logger.exception('')
                custom_message_box(icon=QMessageBox.Warning,
                                   parent=None,
                                   title=_('Error'),
                                   text=_('Cannot load wallet') + ' (1):\n' + repr(e))
                # if app is starting, still let wizard appear
                if not app_is_starting:
                    return
        # Open a wizard window. This lets the user e.g. enter a password, or select
        # a different wallet.
        try:
            if not wallet:
                wallet = self._start_wizard_to_select_or_create_wallet(path)
            if not wallet:
                return
            # create or raise window
            for window in self.windows:
                if window.wallet.storage.path == wallet.storage.path:
                    break
            else:
                window = self._create_window_for_wallet(wallet)
        except Exception as e:
            self.logger.exception('')
            custom_message_box(icon=QMessageBox.Warning,
                               parent=None,
                               title=_('Error'),
                               text=_('Cannot load wallet') + '(2) :\n' + repr(e))
            if app_is_starting:
                # If we raise in this context, there are no more fallbacks, we will shut down.
                # Worst case scenario, we might have gotten here without user interaction,
                # in which case, if we raise now without user interaction, the same sequence of
                # events is likely to repeat when the user restarts the process.
                # So we play it safe: clear path, clear uri, force a wizard to appear.
                try:
                    wallet_dir = os.path.dirname(path)
                    filename = get_new_wallet_name(wallet_dir)
                except OSError:
                    path = self.config.get_fallback_wallet_path()
                else:
                    path = os.path.join(wallet_dir, filename)
                self.start_new_window(path, uri=None, force_wizard=True)
            return
        if uri:
            window.pay_to_URI(uri)
        window.bring_to_top()
        window.setWindowState(window.windowState() & ~QtCore.Qt.WindowMinimized | QtCore.Qt.WindowActive)

        window.activateWindow()
        return window

    def _start_wizard_to_select_or_create_wallet(self, path) -> Optional[Abstract_Wallet]:
        wizard = InstallWizard(self.config, self.app, self.plugins, gui_object=self)
        try:
            path, storage = wizard.select_storage(path, self.daemon.get_wallet)
            # storage is None if file does not exist
            if storage is None:
                wizard.path = path  # needed by trustedcoin plugin
                wizard.run('new')
                storage, db = wizard.create_storage(path)
            else:
                db = WalletDB(storage.read(), manual_upgrades=False)
                wizard.run_upgrades(storage, db)
        except (UserCancelled, GoBack):
            return
        except WalletAlreadyOpenInMemory as e:
            return e.wallet
        finally:
            wizard.terminate()
        # return if wallet creation is not complete
        if storage is None or db.get_action():
            return
        wallet = Wallet(db, storage, config=self.config)
        wallet.start_network(self.daemon.network)
        self.daemon.add_wallet(wallet)
        return wallet

    def close_window(self, window: ElectrumWindow):
        if window in self.windows:
            self.windows.remove(window)
        self.build_tray_menu()
        # save wallet path of last open window
        if not self.windows:
            self.config.save_last_wallet(window.wallet)
        run_hook('on_close_window', window)
        self.daemon.stop_wallet(window.wallet.storage.path)

    def init_network(self):
        # Show network dialog if config does not exist
        if self.daemon.network:
            if self.config.get('auto_connect') is None:
                wizard = InstallWizard(self.config, self.app, self.plugins, gui_object=self)
                wizard.init_network(self.daemon.network)
                wizard.terminate()

    def main(self):
        # setup Ctrl-C handling and tear-down code first, so that user can easily exit whenever
        self.app.setQuitOnLastWindowClosed(False)  # so _we_ can decide whether to quit
        self.app.lastWindowClosed.connect(self._maybe_quit_if_no_windows_open)
        self.app.aboutToQuit.connect(self._cleanup_before_exit)
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())
        # first-start network-setup
        try:
            self.init_network()
        except UserCancelled:
            return
        except GoBack:
            return
        except Exception as e:
            self.logger.exception('')
            return
        # start wizard to select/create wallet
        self.timer.start()
        path = self.config.get_wallet_path(use_gui_last_wallet=True)
        try:
            if not self.start_new_window(path, self.config.get('url'), app_is_starting=True):
                return
        except Exception as e:
            self.logger.error(f"error loading wallet (or creating window for it): {e}")
            # Let Qt event loop start properly so that crash reporter window can appear.
            # We will shutdown when the user closes that window, via lastWindowClosed signal.
        # main loop
        self.logger.info("starting Qt main loop")
        self.app.exec_()
        # on some platforms the exec_ call may not return, so use _cleanup_before_exit

    def stop(self):
        self.logger.info('closing GUI')
        self.app.quit_signal.emit()

    @classmethod
    def version_info(cls):
        ret = {
            "qt.version": QtCore.QT_VERSION_STR,
            "pyqt.version": QtCore.PYQT_VERSION_STR,
        }
        if hasattr(PyQt5, "__path__"):
            ret["pyqt.path"] = ", ".join(PyQt5.__path__ or [])
        return ret
