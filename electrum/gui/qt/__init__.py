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
from typing import Optional, TYPE_CHECKING

from .theme_helper import set_qtum_theme_if_needed

try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import (QApplication, QSystemTrayIcon, QWidget, QMenu,
                             QMessageBox)
from PyQt5.QtCore import QObject, pyqtSignal, QTimer
import PyQt5.QtCore as QtCore

from electrum.i18n import _, set_language
from electrum.plugin import run_hook
from electrum.base_wizard import GoBack
from electrum.util import (UserCancelled, profiler,
                           WalletFileException, BitcoinException, get_new_wallet_name)
from electrum.wallet import Wallet, Abstract_Wallet
from electrum.logging import Logger

from .installwizard import InstallWizard, WalletAlreadyOpenInMemory
from .util import get_default_language, read_QIcon, ColorScheme, custom_message_box
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
                self.windows[0].pay_to_URI(event.url().toEncoded())
                return True
        return False


class QElectrumApplication(QApplication):
    new_window_signal = pyqtSignal(str, object)


class QNetworkUpdatedSignalObject(QObject):
    network_updated_signal = pyqtSignal(str, object)


class ElectrumGui(Logger):

    @profiler
    def __init__(self, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        set_language(config.get('language', get_default_language()))
        Logger.__init__(self)
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
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QElectrumApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.app.setWindowIcon(read_QIcon("electrum.png"))
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
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('Electrum')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.app.new_window_signal.connect(self.start_new_window)
        set_qtum_theme_if_needed(self.config)
        run_hook('init_qt', self)

    def build_tray_menu(self):
        # Avoid immediate GC of old menu when window closed via its action
        if self.tray.contextMenu() is None:
            m = QMenu()
            self.tray.setContextMenu(m)
        else:
            m = self.tray.contextMenu()
            m.clear()
        network = self.daemon.network
        m.addAction(_("Network"), self.show_network_dialog)
        if network.lngossip:
            m.addAction(_("Lightning Network"), self.show_lightning_dialog)
        if network.local_watchtower:
            m.addAction(_("Local Watchtower"), self.show_watchtower_dialog)
        for window in self.windows:
            name = window.wallet.basename()
            submenu = m.addMenu(name)
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            submenu.addAction(_("Close"), window.close)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electrum"), self.close)

    def tray_icon(self):
        if self.dark_icon:
            return read_QIcon('electrum_dark_icon.png')
        else:
            return read_QIcon('electrum_light_icon.png')

    def toggle_tray_icon(self):
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

    def close(self):
        for window in self.windows:
            window.close()
        if self.network_dialog:
            self.network_dialog.close()
        if self.lightning_dialog:
            self.lightning_dialog.close()
        if self.watchtower_dialog:
            self.watchtower_dialog.close()

    def new_window(self, path, uri=None):
        # Use a signal as can be called from daemon thread
        self.app.new_window_signal.emit(path, uri)

    def show_lightning_dialog(self):
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
        self.network_dialog = NetworkDialog(self.daemon.network, self.config,
                                self.network_updated_signal_obj)
        self.network_dialog.show()

    def _create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        self.build_tray_menu()
        # FIXME: Remove in favour of the load_wallet hook
        run_hook('on_new_window', w)
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
        return wrapper

    @count_wizards_in_progress
    def start_new_window(self, path, uri, *, app_is_starting=False):
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it'''
        wallet = None
        try:
            wallet = self.daemon.load_wallet(path, None)
        except BaseException as e:
            self.logger.exception('')
            custom_message_box(icon=QMessageBox.Warning,
                               parent=None,
                               title=_('Error'),
                               text=_('Cannot load wallet') + ' (1):\n' + repr(e))
            # if app is starting, still let wizard to appear
            if not app_is_starting:
                return
        if not wallet:
            try:
                wallet = self._start_wizard_to_select_or_create_wallet(path)
            except (WalletFileException, BitcoinException) as e:
                self.logger.exception('')
                custom_message_box(icon=QMessageBox.Warning,
                                   parent=None,
                                   title=_('Error'),
                                   text=_('Cannot load wallet') + ' (2):\n' + repr(e))
        if not wallet:
            return
        # create or raise window
        try:
            for window in self.windows:
                if window.wallet.storage.path == wallet.storage.path:
                    break
            else:
                window = self._create_window_for_wallet(wallet)
        except BaseException as e:
            self.logger.exception('')
            custom_message_box(icon=QMessageBox.Warning,
                               parent=None,
                               title=_('Error'),
                               text=_('Cannot create window for wallet') + ':\n' + repr(e))
            if app_is_starting:
                wallet_dir = os.path.dirname(path)
                path = os.path.join(wallet_dir, get_new_wallet_name(wallet_dir))
                self.start_new_window(path, uri)
            return
        if uri:
            window.pay_to_URI(uri)
        window.bring_to_top()
        window.setWindowState(window.windowState() & ~QtCore.Qt.WindowMinimized | QtCore.Qt.WindowActive)

        window.activateWindow()
        return window

    def _start_wizard_to_select_or_create_wallet(self, path) -> Optional[Abstract_Wallet]:
        wizard = InstallWizard(self.config, self.app, self.plugins)
        try:
            path, storage = wizard.select_storage(path, self.daemon.get_wallet)
            # storage is None if file does not exist
            if storage is None:
                wizard.path = path  # needed by trustedcoin plugin
                wizard.run('new')
                storage = wizard.create_storage(path)
            else:
                wizard.run_upgrades(storage)
        except (UserCancelled, GoBack):
            return
        except WalletAlreadyOpenInMemory as e:
            return e.wallet
        finally:
            wizard.terminate()
        # return if wallet creation is not complete
        if storage is None or storage.get_action():
            return
        wallet = Wallet(storage, config=self.config)
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
                wizard = InstallWizard(self.config, self.app, self.plugins)
                wizard.init_network(self.daemon.network)
                wizard.terminate()

    def main(self):
        try:
            self.init_network()
        except UserCancelled:
            return
        except GoBack:
            return
        except BaseException as e:
            self.logger.exception('')
            return
        self.timer.start()

        path = self.config.get_wallet_path(use_gui_last_wallet=True)
        if not self.start_new_window(path, self.config.get('url'), app_is_starting=True):
            return
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        def quit_after_last_window():
            # keep daemon running after close
            if self.config.get('daemon'):
                return
            # check if a wizard is in progress
            with self._num_wizards_lock:
                if self._num_wizards_in_progress > 0 or len(self.windows) > 0:
                    return
                if self.config.get('persist_daemon'):
                    return
            self.app.quit()
        self.app.setQuitOnLastWindowClosed(False)  # so _we_ can decide whether to quit
        self.app.lastWindowClosed.connect(quit_after_last_window)

        def clean_up():
            # Shut down the timer cleanly
            self.timer.stop()
            # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
            event = QtCore.QEvent(QtCore.QEvent.Clipboard)
            self.app.sendEvent(self.app.clipboard(), event)
            self.tray.hide()
        self.app.aboutToQuit.connect(clean_up)

        # main loop
        self.app.exec_()
        # on some platforms the exec_ call may not return, so use clean_up()

    def stop(self):
        self.logger.info('closing GUI')
        self.app.quit()
