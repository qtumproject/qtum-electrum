import asyncio
import os.path
import time
import sys
import platform
import queue
import traceback
import os
import webbrowser
from decimal import Decimal
from functools import partial, lru_cache
from typing import (NamedTuple, Callable, Optional, TYPE_CHECKING, Union, List, Dict, Any,
                    Sequence, Iterable)

from PyQt5.QtGui import (QFont, QColor, QCursor, QPixmap, QStandardItem, QImage,
                         QPalette, QIcon, QFontMetrics, QShowEvent, QPainter)
from PyQt5.QtCore import (Qt, QPersistentModelIndex, QModelIndex, pyqtSignal,
                          QCoreApplication, QItemSelectionModel, QThread,
                          QSortFilterProxyModel, QSize, QLocale, QAbstractItemModel,
                          QEvent, QRect, QPoint, QObject)
from PyQt5.QtWidgets import (QPushButton, QLabel, QMessageBox, QHBoxLayout,
                             QAbstractItemView, QVBoxLayout, QLineEdit,
                             QStyle, QDialog, QGroupBox, QButtonGroup, QRadioButton,
                             QFileDialog, QWidget, QToolButton, QTreeView, QPlainTextEdit,
                             QHeaderView, QApplication, QToolTip, QTreeWidget, QStyledItemDelegate,
                             QMenu, QStyleOptionViewItem, QLayout, QLayoutItem, QAbstractButton,
                             QGraphicsEffect, QGraphicsScene, QGraphicsPixmapItem)

from electrum.i18n import _, languages
from electrum.util import FileImportFailed, FileExportFailed, make_aiohttp_session, resource_path
from electrum.invoices import PR_UNPAID, PR_PAID, PR_EXPIRED, PR_INFLIGHT, PR_UNKNOWN, PR_FAILED, PR_ROUTING
from electrum.logging import Logger
from electrum.qrreader import MissingQrDetectionLib

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .installwizard import InstallWizard
    from electrum.simple_config import SimpleConfig


if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'


dialogs = []

pr_icons = {
    PR_UNKNOWN:"warning.png",
    PR_UNPAID:"unpaid.png",
    PR_PAID:"confirmed.png",
    PR_EXPIRED:"expired.png",
    PR_INFLIGHT:"unconfirmed.png",
    PR_FAILED:"warning.png",
    PR_ROUTING:"unconfirmed.png",
}

# note: this list needs to be kept in sync with another in kivy
TX_ICONS = [
    "unconfirmed.png",
    "warning.png",
    "unconfirmed.png",
    "offline_tx.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "confirmed.png",
]

# filter tx files in QFileDialog:
TRANSACTION_FILE_EXTENSION_FILTER_ANY = "Transaction (*.txn *.psbt);;All files (*)"
TRANSACTION_FILE_EXTENSION_FILTER_ONLY_PARTIAL_TX = "Partial Transaction (*.psbt)"
TRANSACTION_FILE_EXTENSION_FILTER_ONLY_COMPLETE_TX = "Complete Transaction (*.txn)"
TRANSACTION_FILE_EXTENSION_FILTER_SEPARATE = (f"{TRANSACTION_FILE_EXTENSION_FILTER_ONLY_PARTIAL_TX};;"
                                              f"{TRANSACTION_FILE_EXTENSION_FILTER_ONLY_COMPLETE_TX};;"
                                              f"All files (*)")


class EnterButton(QPushButton):
    def __init__(self, text, func):
        QPushButton.__init__(self, text)
        self.func = func
        self.clicked.connect(func)

    def keyPressEvent(self, e):
        if e.key() in [Qt.Key_Return, Qt.Key_Enter]:
            self.func()


class ThreadedButton(QPushButton):
    def __init__(self, text, task, on_success=None, on_error=None):
        QPushButton.__init__(self, text)
        self.task = task
        self.on_success = on_success
        self.on_error = on_error
        self.clicked.connect(self.run_task)

    def run_task(self):
        self.setEnabled(False)
        self.thread = TaskThread(self)
        self.thread.add(self.task, self.on_success, self.done, self.on_error)

    def done(self):
        self.setEnabled(True)
        self.thread.stop()


class WWLabel(QLabel):
    def __init__ (self, text="", parent=None):
        QLabel.__init__(self, text, parent)
        self.setWordWrap(True)
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)


class HelpLabel(QLabel):

    def __init__(self, text, help_text):
        QLabel.__init__(self, text)
        self.help_text = help_text
        self.app = QCoreApplication.instance()
        self.font = QFont()

    def mouseReleaseEvent(self, x):
        custom_message_box(icon=QMessageBox.Information,
                           parent=self,
                           title=_('Help'),
                           text=self.help_text)

    def enterEvent(self, event):
        self.font.setUnderline(True)
        self.setFont(self.font)
        self.app.setOverrideCursor(QCursor(Qt.PointingHandCursor))
        return QLabel.enterEvent(self, event)

    def leaveEvent(self, event):
        self.font.setUnderline(False)
        self.setFont(self.font)
        self.app.setOverrideCursor(QCursor(Qt.ArrowCursor))
        return QLabel.leaveEvent(self, event)


class HelpButton(QToolButton):
    def __init__(self, text):
        QToolButton.__init__(self)
        self.setText('?')
        self.help_text = text
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(round(2.2 * char_width_in_lineedit()))
        self.clicked.connect(self.onclick)

    def onclick(self):
        custom_message_box(icon=QMessageBox.Information,
                           parent=self,
                           title=_('Help'),
                           text=self.help_text,
                           rich_text=True)


class InfoButton(QPushButton):
    def __init__(self, text):
        QPushButton.__init__(self, 'Info')
        self.help_text = text
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(6 * char_width_in_lineedit())
        self.clicked.connect(self.onclick)

    def onclick(self):
        custom_message_box(icon=QMessageBox.Information,
                           parent=self,
                           title=_('Info'),
                           text=self.help_text,
                           rich_text=True)


class Buttons(QHBoxLayout):
    def __init__(self, *buttons):
        QHBoxLayout.__init__(self)
        self.addStretch(1)
        for b in buttons:
            if b is None:
                continue
            self.addWidget(b)

class CloseButton(QPushButton):
    def __init__(self, dialog):
        QPushButton.__init__(self, _("Close"))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class CopyButton(QPushButton):
    def __init__(self, text_getter, app):
        QPushButton.__init__(self, _("Copy"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))

class CopyCloseButton(QPushButton):
    def __init__(self, text_getter, app, dialog):
        QPushButton.__init__(self, _("Copy and Close"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class OkButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("OK"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CancelButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("Cancel"))
        self.clicked.connect(dialog.reject)

class MessageBoxMixin(object):
    def top_level_window_recurse(self, window=None, test_func=None):
        window = window or self
        classes = (WindowModalDialog, QMessageBox)
        if test_func is None:
            test_func = lambda x: True
        for n, child in enumerate(window.children()):
            # Test for visibility as old closed dialogs may not be GC-ed.
            # Only accept children that confirm to test_func.
            if isinstance(child, classes) and child.isVisible() \
                    and test_func(child):
                return self.top_level_window_recurse(child, test_func=test_func)
        return window

    def top_level_window(self, test_func=None):
        return self.top_level_window_recurse(test_func)

    def question(self, msg, parent=None, title=None, icon=None, **kwargs) -> bool:
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return Yes == self.msg_box(icon=icon or QMessageBox.Question,
                                   parent=parent,
                                   title=title or '',
                                   text=msg,
                                   buttons=Yes|No,
                                   defaultButton=No,
                                   **kwargs)

    def show_warning(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Warning'), msg, **kwargs)

    def show_error(self, msg, parent=None, **kwargs):
        return self.msg_box(QMessageBox.Warning, parent,
                            _('Error'), msg, **kwargs)

    def show_critical(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Critical, parent,
                            title or _('Critical Error'), msg, **kwargs)

    def show_message(self, msg, parent=None, title=None, **kwargs):
        return self.msg_box(QMessageBox.Information, parent,
                            title or _('Information'), msg, **kwargs)

    def msg_box(self, icon, parent, title, text, *, buttons=QMessageBox.Ok,
                defaultButton=QMessageBox.NoButton, rich_text=False,
                checkbox=None):
        parent = parent or self.top_level_window()
        return custom_message_box(icon=icon,
                                  parent=parent,
                                  title=title,
                                  text=text,
                                  buttons=buttons,
                                  defaultButton=defaultButton,
                                  rich_text=rich_text,
                                  checkbox=checkbox)


def custom_message_box(*, icon, parent, title, text, buttons=QMessageBox.Ok,
                       defaultButton=QMessageBox.NoButton, rich_text=False,
                       checkbox=None):
    if type(icon) is QPixmap:
        d = QMessageBox(QMessageBox.Information, title, str(text), buttons, parent)
        d.setIconPixmap(icon)
    else:
        d = QMessageBox(icon, title, str(text), buttons, parent)
    d.setWindowModality(Qt.WindowModal)
    d.setDefaultButton(defaultButton)
    if rich_text:
        d.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
        # set AutoText instead of RichText
        # AutoText lets Qt figure out whether to render as rich text.
        # e.g. if text is actually plain text and uses "\n" newlines;
        #      and we set RichText here, newlines would be swallowed
        d.setTextFormat(Qt.AutoText)
    else:
        d.setTextInteractionFlags(Qt.TextSelectableByMouse)
        d.setTextFormat(Qt.PlainText)
    if checkbox is not None:
        d.setCheckBox(checkbox)
    d.setStyleSheet("QLabel{max-height: 150px;}")
    return d.exec_()


class WindowModalDialog(QDialog, MessageBoxMixin):
    '''Handy wrapper; window modal dialogs are better for our multi-window
    daemon model as other wallet windows can still be accessed.'''
    def __init__(self, parent, title=None):
        QDialog.__init__(self, parent)
        self.setWindowModality(Qt.WindowModal)
        if title:
            self.setWindowTitle(title)


class WaitingDialog(WindowModalDialog):
    '''Shows a please wait dialog whilst running a task.  It is not
    necessary to maintain a reference to this dialog.'''
    def __init__(self, parent: QWidget, message: str, task, on_success=None, on_error=None):
        assert parent
        if isinstance(parent, MessageBoxMixin):
            parent = parent.top_level_window()
        WindowModalDialog.__init__(self, parent, _("Please wait"))
        self.message_label = QLabel(message)
        vbox = QVBoxLayout(self)
        vbox.addWidget(self.message_label)
        self.accepted.connect(self.on_accepted)
        self.show()
        self.thread = TaskThread(self)
        self.thread.finished.connect(self.deleteLater)  # see #3956
        self.thread.add(task, on_success, self.accept, on_error)

    def wait(self):
        self.thread.wait()

    def on_accepted(self):
        self.thread.stop()

    def update(self, msg):
        self.message_label.setText(msg)


class BlockingWaitingDialog(WindowModalDialog):
    """Shows a waiting dialog whilst running a task.
    Should be called from the GUI thread. The GUI thread will be blocked while
    the task is running; the point of the dialog is to provide feedback
    to the user regarding what is going on.
    """
    def __init__(self, parent: QWidget, message: str, task: Callable[[], Any]):
        assert parent
        if isinstance(parent, MessageBoxMixin):
            parent = parent.top_level_window()
        WindowModalDialog.__init__(self, parent, _("Please wait"))
        self.message_label = QLabel(message)
        vbox = QVBoxLayout(self)
        vbox.addWidget(self.message_label)
        # show popup
        self.show()
        # refresh GUI; needed for popup to appear and for message_label to get drawn
        QCoreApplication.processEvents()
        QCoreApplication.processEvents()
        # block and run given task
        try:
            task()
        except BaseException as e:
            self.reject()
            raise e
        else:
            # close popup
            self.accept()


def line_dialog(parent, title, label, ok_label, default=None):
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(500)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    txt = QLineEdit()
    if default:
        txt.setText(default)
    l.addWidget(txt)
    l.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, ok_label)))
    if dialog.exec_():
        return txt.text()

def text_dialog(
        *,
        parent,
        title,
        header_layout,
        ok_label,
        default=None,
        allow_multi=False,
        config: 'SimpleConfig',
):
    from .qrtextedit import ScanQRTextEdit
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(600)
    l = QVBoxLayout()
    dialog.setLayout(l)
    if isinstance(header_layout, str):
        l.addWidget(QLabel(header_layout))
    else:
        l.addLayout(header_layout)
    txt = ScanQRTextEdit(allow_multi=allow_multi, config=config)
    if default:
        txt.setText(default)
    l.addWidget(txt)
    l.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, ok_label)))
    if dialog.exec_():
        return txt.toPlainText()

class ChoicesLayout(object):
    def __init__(self, msg, choices, on_clicked=None, checked_index=0):
        vbox = QVBoxLayout()
        if len(msg) > 50:
            vbox.addWidget(WWLabel(msg))
            msg = ""
        gb2 = QGroupBox(msg)
        vbox.addWidget(gb2)
        vbox2 = QVBoxLayout()
        gb2.setLayout(vbox2)
        self.group = group = QButtonGroup()
        if isinstance(choices, list):
            iterator = enumerate(choices)
        else:
            iterator = choices.items()
        for i, c in iterator:
            button = QRadioButton(gb2)
            button.setText(c)
            vbox2.addWidget(button)
            group.addButton(button)
            group.setId(button, i)
            if i == checked_index:
                button.setChecked(True)
        if on_clicked:
            group.buttonClicked.connect(partial(on_clicked, self))
        self.vbox = vbox

    def layout(self):
        return self.vbox

    def selected_index(self):
        return self.group.checkedId()

def address_field(addresses):
    hbox = QHBoxLayout()
    address_e = QLineEdit()
    if addresses and len(addresses) > 0:
        address_e.setText(addresses[0])
    else:
        addresses = []
    def func():
        try:
            i = addresses.index(str(address_e.text())) + 1
            i = i % len(addresses)
            address_e.setText(addresses[i])
        except ValueError:
            # the user might have changed address_e to an
            # address not in the wallet (or to something that isn't an address)
            if addresses and len(addresses) > 0:
                address_e.setText(addresses[0])
    button = QPushButton(_('Address'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(address_e)
    return hbox, address_e


def filename_field(parent, config, defaultname, select_msg):

    vbox = QVBoxLayout()
    vbox.addWidget(QLabel(_("Format")))
    gb = QGroupBox("format", parent)
    b1 = QRadioButton(gb)
    b1.setText(_("CSV"))
    b1.setChecked(True)
    b2 = QRadioButton(gb)
    b2.setText(_("json"))
    vbox.addWidget(b1)
    vbox.addWidget(b2)

    hbox = QHBoxLayout()

    directory = config.get('io_dir', os.path.expanduser('~'))
    path = os.path.join(directory, defaultname)
    filename_e = QLineEdit()
    filename_e.setText(path)

    def func():
        text = filename_e.text()
        _filter = "*.csv" if defaultname.endswith(".csv") else "*.json" if defaultname.endswith(".json") else None
        p = getSaveFileName(
            parent=None,
            title=select_msg,
            filename=text,
            filter=_filter,
            config=config,
        )
        if p:
            filename_e.setText(p)

    button = QPushButton(_('File'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(filename_e)
    vbox.addLayout(hbox)

    def set_csv(v):
        text = filename_e.text()
        text = text.replace(".json",".csv") if v else text.replace(".csv",".json")
        filename_e.setText(text)

    b1.clicked.connect(lambda: set_csv(True))
    b2.clicked.connect(lambda: set_csv(False))

    return vbox, filename_e, b1


class ElectrumItemDelegate(QStyledItemDelegate):
    def __init__(self, tv: 'MyTreeView'):
        super().__init__(tv)
        self.tv = tv
        self.opened = None
        def on_closeEditor(editor: QLineEdit, hint):
            self.opened = None
            self.tv.is_editor_open = False
            if self.tv._pending_update:
                self.tv.update()
        def on_commitData(editor: QLineEdit):
            new_text = editor.text()
            idx = QModelIndex(self.opened)
            row, col = idx.row(), idx.column()
            _prior_text, user_role = self.tv.get_text_and_userrole_from_coordinate(row, col)
            # check that we didn't forget to set UserRole on an editable field
            assert user_role is not None, (row, col)
            self.tv.on_edited(idx, user_role, new_text)
        self.closeEditor.connect(on_closeEditor)
        self.commitData.connect(on_commitData)

    def createEditor(self, parent, option, idx):
        self.opened = QPersistentModelIndex(idx)
        self.tv.is_editor_open = True
        return super().createEditor(parent, option, idx)


class MyTreeView(QTreeView):
    ROLE_CLIPBOARD_DATA = Qt.UserRole + 100

    filter_columns: Iterable[int]

    def __init__(self, parent: 'ElectrumWindow', create_menu, *,
                 stretch_column=None, editable_columns=None):
        super().__init__(parent)
        self.parent = parent
        self.config = self.parent.config
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        self.setUniformRowHeights(True)

        # Control which columns are editable
        if editable_columns is not None:
            editable_columns = set(editable_columns)
        elif stretch_column is not None:
            editable_columns = {stretch_column}
        else:
            editable_columns = {}
        self.editable_columns = editable_columns
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.current_filter = ""
        self.is_editor_open = False

        self.setRootIsDecorated(False)  # remove left margin
        self.toolbar_shown = False

        # When figuring out the size of columns, Qt by default looks at
        # the first 1000 rows (at least if resize mode is QHeaderView.ResizeToContents).
        # This would be REALLY SLOW, and it's not perfect anyway.
        # So to speed the UI up considerably, set it to
        # only look at as many rows as currently visible.
        self.header().setResizeContentsPrecision(0)

        self._pending_update = False
        self._forced_update = False

    def set_editability(self, items):
        for idx, i in enumerate(items):
            i.setEditable(idx in self.editable_columns)

    def selected_in_column(self, column: int):
        items = self.selectionModel().selectedIndexes()
        return list(x for x in items if x.column() == column)

    def current_item_user_role(self, col) -> Any:
        idx = self.selectionModel().currentIndex()
        idx = idx.sibling(idx.row(), col)
        item = self.item_from_index(idx)
        if item:
            return item.data(Qt.UserRole)

    def item_from_index(self, idx: QModelIndex) -> Optional[QStandardItem]:
        model = self.model()
        if isinstance(model, QSortFilterProxyModel):
            idx = model.mapToSource(idx)
            return model.sourceModel().itemFromIndex(idx)
        else:
            return model.itemFromIndex(idx)

    def original_model(self) -> QAbstractItemModel:
        model = self.model()
        if isinstance(model, QSortFilterProxyModel):
            return model.sourceModel()
        else:
            return model

    def set_current_idx(self, set_current: QPersistentModelIndex):
        if set_current:
            assert isinstance(set_current, QPersistentModelIndex)
            assert set_current.isValid()
            self.selectionModel().select(QModelIndex(set_current), QItemSelectionModel.SelectCurrent)

    def update_headers(self, headers: Union[List[str], Dict[int, str]]):
        # headers is either a list of column names, or a dict: (col_idx->col_name)
        if not isinstance(headers, dict):  # convert to dict
            headers = dict(enumerate(headers))
        col_names = [headers[col_idx] for col_idx in sorted(headers.keys())]
        self.original_model().setHorizontalHeaderLabels(col_names)
        self.header().setStretchLastSection(False)
        for col_idx in headers:
            sm = QHeaderView.Stretch if col_idx == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col_idx, sm)

    def keyPressEvent(self, event):
        if self.itemDelegate().opened:
            return
        if event.key() in [Qt.Key_F2, Qt.Key_Return, Qt.Key_Enter]:
            self.on_activated(self.selectionModel().currentIndex())
            return
        super().keyPressEvent(event)

    def on_activated(self, idx):
        # on 'enter' we show the menu
        pt = self.visualRect(idx).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def edit(self, idx, trigger=QAbstractItemView.AllEditTriggers, event=None):
        """
        this is to prevent:
           edit: editing failed
        from inside qt
        """
        return super().edit(idx, trigger, event)

    def on_edited(self, idx: QModelIndex, user_role, text):
        self.parent.wallet.set_label(user_role, text)
        self.parent.history_model.refresh('on_edited in MyTreeView')
        self.parent.utxo_list.update()
        self.parent.update_completions()

    def should_hide(self, row):
        """
        row_num is for self.model(). So if there is a proxy, it is the row number
        in that!
        """
        return False

    def get_text_and_userrole_from_coordinate(self, row_num, column):
        idx = self.model().index(row_num, column)
        item = self.item_from_index(idx)
        user_role = item.data(Qt.UserRole)
        return item.text(), user_role

    def hide_row(self, row_num):
        """
        row_num is for self.model(). So if there is a proxy, it is the row number
        in that!
        """
        should_hide = self.should_hide(row_num)
        if not self.current_filter and should_hide is None:
            # no filters at all, neither date nor search
            self.setRowHidden(row_num, QModelIndex(), False)
            return
        for column in self.filter_columns:
            txt, __ = self.get_text_and_userrole_from_coordinate(row_num, column)
            txt = txt.lower()
            if self.current_filter in txt:
                # the filter matched, but the date filter might apply
                self.setRowHidden(row_num, QModelIndex(), bool(should_hide))
                break
        else:
            # we did not find the filter in any columns, hide the item
            self.setRowHidden(row_num, QModelIndex(), True)

    def filter(self, p=None):
        if p is not None:
            p = p.lower()
            self.current_filter = p
        self.hide_rows()

    def hide_rows(self):
        for row in range(self.model().rowCount()):
            self.hide_row(row)

    def create_toolbar(self, config=None):
        hbox = QHBoxLayout()
        buttons = self.get_toolbar_buttons()
        for b in buttons:
            b.setVisible(False)
            hbox.addWidget(b)
        hide_button = QPushButton('x')
        hide_button.setVisible(False)
        hide_button.pressed.connect(lambda: self.show_toolbar(False, config))
        self.toolbar_buttons = buttons + (hide_button,)
        hbox.addStretch()
        hbox.addWidget(hide_button)
        return hbox

    def save_toolbar_state(self, state, config):
        pass  # implemented in subclasses

    def show_toolbar(self, state, config=None):
        if state == self.toolbar_shown:
            return
        self.toolbar_shown = state
        if config:
            self.save_toolbar_state(state, config)
        for b in self.toolbar_buttons:
            b.setVisible(state)
        if not state:
            self.on_hide_toolbar()

    def toggle_toolbar(self, config=None):
        self.show_toolbar(not self.toolbar_shown, config)

    def add_copy_menu(self, menu: QMenu, idx) -> QMenu:
        cc = menu.addMenu(_("Copy"))
        for column in self.Columns:
            column_title = self.original_model().horizontalHeaderItem(column).text()
            if not column_title:
                continue
            item_col = self.item_from_index(idx.sibling(idx.row(), column))
            clipboard_data = item_col.data(self.ROLE_CLIPBOARD_DATA)
            if clipboard_data is None:
                clipboard_data = item_col.text().strip()
            cc.addAction(column_title,
                         lambda text=clipboard_data, title=column_title:
                         self.place_text_on_clipboard(text, title=title))
        return cc

    def place_text_on_clipboard(self, text: str, *, title: str = None) -> None:
        self.parent.do_copy(text, title=title)

    def showEvent(self, e: 'QShowEvent'):
        super().showEvent(e)
        if e.isAccepted() and self._pending_update:
            self._forced_update = True
            self.update()
            self._forced_update = False

    def maybe_defer_update(self) -> bool:
        """Returns whether we should defer an update/refresh."""
        defer = (not self._forced_update
                 and (not self.isVisible() or self.is_editor_open))
        # side-effect: if we decide to defer update, the state will become stale:
        self._pending_update = defer
        return defer


class MySortModel(QSortFilterProxyModel):
    def __init__(self, parent, *, sort_role):
        super().__init__(parent)
        self._sort_role = sort_role

    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex):
        item1 = self.sourceModel().itemFromIndex(source_left)
        item2 = self.sourceModel().itemFromIndex(source_right)
        data1 = item1.data(self._sort_role)
        data2 = item2.data(self._sort_role)
        if data1 is not None and data2 is not None:
            return data1 < data2
        v1 = item1.text()
        v2 = item2.text()
        try:
            return Decimal(v1) < Decimal(v2)
        except:
            return v1 < v2


class OverlayControlMixin:
    STYLE_SHEET_COMMON = '''
    QPushButton { border-width: 1px; padding: 0px; margin: 0px; }
    '''

    STYLE_SHEET_LIGHT = '''
    QPushButton { border: 1px solid transparent; }
    QPushButton:hover { border: 1px solid #3daee9; }
    '''

    def __init__(self, middle: bool = False):
        assert isinstance(self, QWidget)
        assert isinstance(self, OverlayControlMixin)  # only here for type-hints in IDE
        self.middle = middle
        self.overlay_widget = QWidget(self)
        style_sheet = self.STYLE_SHEET_COMMON
        if not ColorScheme.dark_scheme:
            style_sheet = style_sheet + self.STYLE_SHEET_LIGHT
        self.overlay_widget.setStyleSheet(style_sheet)
        self.overlay_layout = QHBoxLayout(self.overlay_widget)
        self.overlay_layout.setContentsMargins(0, 0, 0, 0)
        self.overlay_layout.setSpacing(1)
        self._updateOverlayPos()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._updateOverlayPos()

    def _updateOverlayPos(self):
        frame_width = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        overlay_size = self.overlay_widget.sizeHint()
        x = self.rect().right() - frame_width - overlay_size.width()
        y = self.rect().bottom() - overlay_size.height()
        middle = self.middle
        if hasattr(self, 'document'):
            # Keep the buttons centered if we have less than 2 lines in the editor
            line_spacing = QFontMetrics(self.document().defaultFont()).lineSpacing()
            if self.rect().height() < (line_spacing * 2):
                middle = True
        y = (y / 2) + frame_width if middle else y - frame_width
        if hasattr(self, 'verticalScrollBar') and self.verticalScrollBar().isVisible():
            scrollbar_width = self.style().pixelMetric(QStyle.PM_ScrollBarExtent)
            x -= scrollbar_width
        self.overlay_widget.move(int(x), int(y))

    def addWidget(self, widget: QWidget):
        # The old code positioned the items the other way around, so we just insert at position 0 instead
        self.overlay_layout.insertWidget(0, widget)

    def addButton(self, icon_name: str, on_click, tooltip: str) -> QPushButton:
        button = QPushButton(self.overlay_widget)
        button.setToolTip(tooltip)
        button.setIcon(read_QIcon(icon_name))
        button.setCursor(QCursor(Qt.PointingHandCursor))
        button.clicked.connect(on_click)
        self.addWidget(button)
        return button

    def addCopyButton(self):
        def on_copy():
            app = QApplication.instance()
            app.clipboard().setText(self.text())
            QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), self)

        self.addButton("copy.png", on_copy, _("Copy to clipboard"))

    def addPasteButton(
            self,
            *,
            setText: Callable[[str], None] = None,
    ):
        if setText is None:
            setText = self.setText
        def on_paste():
            app = QApplication.instance()
            setText(app.clipboard().text())

        self.addButton("copy.png", on_paste, _("Paste from clipboard"))

    def add_qr_show_button(self, *, config: 'SimpleConfig', title: Optional[str] = None):
        if title is None:
            title = _("QR code")

        def qr_show():
            from .qrcodewidget import QRDialog
            try:
                s = str(self.text())
            except:
                s = self.text()
            if not s:
                return
            QRDialog(
                data=s,
                parent=self,
                title=title,
                config=config,
            ).exec_()

        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addButton(icon, qr_show, _("Show as QR code"))
        # side-effect: we export this method:
        self.on_qr_show_btn = qr_show

    def add_qr_input_button(
            self,
            *,
            config: 'SimpleConfig',
            allow_multi: bool = False,
            show_error: Callable[[str], None],
            setText: Callable[[str], None] = None,
    ):
        if setText is None:
            setText = self.setText
        def qr_from_camera_input() -> None:
            def cb(success: bool, error: str, data):
                if not success:
                    if error:
                        show_error(error)
                    return
                if not data:
                    data = ''
                if allow_multi:
                    new_text = self.text() + data + '\n'
                else:
                    new_text = data
                setText(new_text)

            from .qrreader import scan_qrcode
            scan_qrcode(parent=self, config=config, callback=cb)

        def qr_from_screenshot_input() -> None:
            from .qrreader import scan_qr_from_image
            scanned_qr = None
            for screen in QApplication.instance().screens():
                try:
                    scan_result = scan_qr_from_image(screen.grabWindow(0).toImage())
                except MissingQrDetectionLib as e:
                    show_error(_("Unable to scan image.") + "\n" + repr(e))
                    return
                if len(scan_result) > 0:
                    if (scanned_qr is not None) or len(scan_result) > 1:
                        show_error(_("More than one QR code was found on the screen."))
                        return
                    scanned_qr = scan_result
            if scanned_qr is None:
                show_error(_("No QR code was found on the screen."))
                return
            data = scanned_qr[0].data
            if allow_multi:
                new_text = self.text() + data + '\n'
            else:
                new_text = data
            setText(new_text)

        icon = "camera_white.png" if ColorScheme.dark_scheme else "camera_dark.png"
        btn = self.addButton(icon, lambda: None, _("Read QR code"))
        menu = QMenu()
        menu.addAction(_("Read QR code from camera"), qr_from_camera_input)
        menu.addAction(_("Read QR code from screen"), qr_from_screenshot_input)
        btn.setMenu(menu)
        # side-effect: we export these methods:
        self.on_qr_from_camera_input_btn = qr_from_camera_input
        self.on_qr_from_screenshot_input_btn = qr_from_screenshot_input

    def add_file_input_button(
            self,
            *,
            config: 'SimpleConfig',
            show_error: Callable[[str], None],
            setText: Callable[[str], None] = None,
    ) -> None:
        if setText is None:
            setText = self.setText
        def file_input():
            fileName = getOpenFileName(
                parent=self,
                title='select file',
                config=config,
            )
            if not fileName:
                return
            try:
                try:
                    with open(fileName, "r") as f:
                        data = f.read()
                except UnicodeError as e:
                    with open(fileName, "rb") as f:
                        data = f.read()
                    data = data.hex()
            except BaseException as e:
                show_error(_('Error opening file') + ':\n' + repr(e))
            else:
                setText(data)

        self.addButton("file.png", file_input, _("Read file"))


class ButtonsLineEdit(OverlayControlMixin, QLineEdit):
    def __init__(self, text=None):
        QLineEdit.__init__(self, text)
        OverlayControlMixin.__init__(self, middle=True)


class ButtonsTextEdit(OverlayControlMixin, QPlainTextEdit):
    def __init__(self, text=None):
        QPlainTextEdit.__init__(self, text)
        OverlayControlMixin.__init__(self)
        self.setText = self.setPlainText
        self.text = self.toPlainText


class PasswordLineEdit(QLineEdit):
    def __init__(self, *args, **kwargs):
        QLineEdit.__init__(self, *args, **kwargs)
        self.setEchoMode(QLineEdit.Password)

    def clear(self):
        # Try to actually overwrite the memory.
        # This is really just a best-effort thing...
        self.setText(len(self.text()) * " ")
        super().clear()


class TaskThread(QThread, Logger):
    '''Thread that runs background tasks.  Callbacks are guaranteed
    to happen in the context of its parent.'''

    class Task(NamedTuple):
        task: Callable
        cb_success: Optional[Callable]
        cb_done: Optional[Callable]
        cb_error: Optional[Callable]
        cancel: Optional[Callable] = None

    doneSig = pyqtSignal(object, object, object)

    def __init__(self, parent, on_error=None):
        QThread.__init__(self, parent)
        Logger.__init__(self)
        self.on_error = on_error
        self.tasks = queue.Queue()
        self._cur_task = None  # type: Optional[TaskThread.Task]
        self._stopping = False
        self.doneSig.connect(self.on_done)
        self.start()

    def add(self, task, on_success=None, on_done=None, on_error=None, cancel=None):
        if self._stopping:
            self.logger.warning(f"stopping or already stopped but tried to add new task.")
            return
        on_error = on_error or self.on_error
        task_ = TaskThread.Task(task, on_success, on_done, on_error, cancel=cancel)
        self.tasks.put(task_)

    def run(self):
        while True:
            if self._stopping:
                break
            task = self.tasks.get()  # type: TaskThread.Task
            self._cur_task = task
            if not task or self._stopping:
                break
            try:
                result = task.task()
                self.doneSig.emit(result, task.cb_done, task.cb_success)
            except BaseException:
                self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)

    def on_done(self, result, cb_done, cb_result):
        # This runs in the parent's thread.
        if cb_done:
            cb_done()
        if cb_result:
            cb_result(result)

    def stop(self):
        self._stopping = True
        # try to cancel currently running task now.
        # if the task does not implement "cancel", we will have to wait until it finishes.
        task = self._cur_task
        if task and task.cancel:
            task.cancel()
        # cancel the remaining tasks in the queue
        while True:
            try:
                task = self.tasks.get_nowait()
            except queue.Empty:
                break
            if task and task.cancel:
                task.cancel()
        self.tasks.put(None)  # in case the thread is still waiting on the queue
        self.exit()
        self.wait()


class ColorSchemeItem:
    def __init__(self, fg_color, bg_color):
        self.colors = (fg_color, bg_color)

    def _get_color(self, background):
        return self.colors[(int(background) + int(ColorScheme.dark_scheme)) % 2]

    def as_stylesheet(self, background=False):
        css_prefix = "background-" if background else ""
        color = self._get_color(background)
        return "QWidget {{ {}color:{}; }}".format(css_prefix, color)

    def as_color(self, background=False):
        color = self._get_color(background)
        return QColor(color)


class ColorScheme:
    dark_scheme = False

    GREEN = ColorSchemeItem("#117c11", "#8af296")
    YELLOW = ColorSchemeItem("#897b2a", "#ffff00")
    RED = ColorSchemeItem("#7c1111", "#f18c8c")
    BLUE = ColorSchemeItem("#123b7c", "#8cb3f2")
    DEFAULT = ColorSchemeItem("black", "white")
    GRAY = ColorSchemeItem("gray", "gray")

    @staticmethod
    def has_dark_background(widget):
        brightness = sum(widget.palette().color(QPalette.Background).getRgb()[0:3])
        return brightness < (255*3/2)

    @staticmethod
    def update_from_widget(widget, force_dark=False):
        if force_dark or ColorScheme.has_dark_background(widget):
            ColorScheme.dark_scheme = True


class AcceptFileDragDrop:
    def __init__(self, file_type=""):
        assert isinstance(self, QWidget)
        self.setAcceptDrops(True)
        self.file_type = file_type

    def validateEvent(self, event):
        if not event.mimeData().hasUrls():
            event.ignore()
            return False
        for url in event.mimeData().urls():
            if not url.toLocalFile().endswith(self.file_type):
                event.ignore()
                return False
        event.accept()
        return True

    def dragEnterEvent(self, event):
        self.validateEvent(event)

    def dragMoveEvent(self, event):
        if self.validateEvent(event):
            event.setDropAction(Qt.CopyAction)

    def dropEvent(self, event):
        if self.validateEvent(event):
            for url in event.mimeData().urls():
                self.onFileAdded(url.toLocalFile())

    def onFileAdded(self, fn):
        raise NotImplementedError()


def import_meta_gui(electrum_window: 'ElectrumWindow', title, importer, on_success):
    filter_ = "JSON (*.json);;All files (*)"
    filename = getOpenFileName(
        parent=electrum_window,
        title=_("Open {} file").format(title),
        filter=filter_,
        config=electrum_window.config,
    )
    if not filename:
        return
    try:
        importer(filename)
    except FileImportFailed as e:
        electrum_window.show_critical(str(e))
    else:
        electrum_window.show_message(_("Your {} were successfully imported").format(title))
        on_success()


def export_meta_gui(electrum_window: 'ElectrumWindow', title, exporter):
    filter_ = "JSON (*.json);;All files (*)"
    filename = getSaveFileName(
        parent=electrum_window,
        title=_("Select file to save your {}").format(title),
        filename='electrum_{}.json'.format(title),
        filter=filter_,
        config=electrum_window.config,
    )
    if not filename:
        return
    try:
        exporter(filename)
    except FileExportFailed as e:
        electrum_window.show_critical(str(e))
    else:
        electrum_window.show_message(_("Your {0} were exported to '{1}'")
                                     .format(title, str(filename)))


def icon_path(icon_basename):
    return resource_path('gui', 'icons', icon_basename)


@lru_cache(maxsize=1000)
def read_QIcon(icon_basename):
    return QIcon(icon_path(icon_basename))


def get_default_language():
    name = QLocale.system().name()
    return name if name in languages else 'en_UK'


def char_width_in_lineedit() -> int:
    char_width = QFontMetrics(QLineEdit().font()).averageCharWidth()
    # 'averageCharWidth' seems to underestimate on Windows, hence 'max()'
    return max(9, char_width)


def webopen(url: str):
    if sys.platform == 'linux' and os.environ.get('APPIMAGE'):
        # When on Linux webbrowser.open can fail in AppImage because it can't find the correct libdbus.
        # We just fork the process and unset LD_LIBRARY_PATH before opening the URL.
        # See #5425
        if os.fork() == 0:
            del os.environ['LD_LIBRARY_PATH']
            webbrowser.open(url)
            os._exit(0)
    else:
        webbrowser.open(url)


class FixedAspectRatioLayout(QLayout):
    def __init__(self, parent: QWidget = None, aspect_ratio: float = 1.0):
        super().__init__(parent)
        self.aspect_ratio = aspect_ratio
        self.items: List[QLayoutItem] = []

    def set_aspect_ratio(self, aspect_ratio: float = 1.0):
        self.aspect_ratio = aspect_ratio
        self.update()

    def addItem(self, item: QLayoutItem):
        self.items.append(item)

    def count(self) -> int:
        return len(self.items)

    def itemAt(self, index: int) -> QLayoutItem:
        if index >= len(self.items):
            return None
        return self.items[index]

    def takeAt(self, index: int) -> QLayoutItem:
        if index >= len(self.items):
            return None
        return self.items.pop(index)

    def _get_contents_margins_size(self) -> QSize:
        margins = self.contentsMargins()
        return QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def setGeometry(self, rect: QRect):
        super().setGeometry(rect)
        if not self.items:
            return

        contents = self.contentsRect()
        if contents.height() > 0:
            c_aratio = contents.width() / contents.height()
        else:
            c_aratio = 1
        s_aratio = self.aspect_ratio
        item_rect = QRect(QPoint(0, 0), QSize(
            contents.width() if c_aratio < s_aratio else int(contents.height() * s_aratio),
            contents.height() if c_aratio > s_aratio else int(contents.width() / s_aratio)
        ))

        content_margins = self.contentsMargins()
        free_space = contents.size() - item_rect.size()

        for item in self.items:
            if free_space.width() > 0 and not item.alignment() & Qt.AlignLeft:
                if item.alignment() & Qt.AlignRight:
                    item_rect.moveRight(contents.width() + content_margins.right())
                else:
                    item_rect.moveLeft(content_margins.left() + (free_space.width() // 2))
            else:
                item_rect.moveLeft(content_margins.left())

            if free_space.height() > 0 and not item.alignment() & Qt.AlignTop:
                if item.alignment() & Qt.AlignBottom:
                    item_rect.moveBottom(contents.height() + content_margins.bottom())
                else:
                    item_rect.moveTop(content_margins.top() + (free_space.height() // 2))
            else:
                item_rect.moveTop(content_margins.top())

            item.widget().setGeometry(item_rect)

    def sizeHint(self) -> QSize:
        result = QSize()
        for item in self.items:
            result = result.expandedTo(item.sizeHint())
        return self._get_contents_margins_size() + result

    def minimumSize(self) -> QSize:
        result = QSize()
        for item in self.items:
            result = result.expandedTo(item.minimumSize())
        return self._get_contents_margins_size() + result

    def expandingDirections(self) -> Qt.Orientations:
        return Qt.Horizontal | Qt.Vertical

def QColorLerp(a: QColor, b: QColor, t: float):
    """
    Blends two QColors. t=0 returns a. t=1 returns b. t=0.5 returns evenly mixed.
    """
    t = max(min(t, 1.0), 0.0)
    i_t = 1.0 - t
    return QColor(
        int((a.red()   * i_t) + (b.red()   * t)),
        int((a.green() * i_t) + (b.green() * t)),
        int((a.blue()  * i_t) + (b.blue()  * t)),
        int((a.alpha() * i_t) + (b.alpha() * t)),
    )


class ImageGraphicsEffect(QObject):
    """
    Applies a QGraphicsEffect to a QImage
    """

    def __init__(self, parent: QObject, effect: QGraphicsEffect):
        super().__init__(parent)
        assert effect, 'effect must be set'
        self.effect = effect
        self.graphics_scene = QGraphicsScene()
        self.graphics_item = QGraphicsPixmapItem()
        self.graphics_item.setGraphicsEffect(effect)
        self.graphics_scene.addItem(self.graphics_item)

    def apply(self, image: QImage):
        assert image, 'image must be set'
        result = QImage(image.size(), QImage.Format_ARGB32)
        result.fill(Qt.transparent)
        painter = QPainter(result)
        self.graphics_item.setPixmap(QPixmap.fromImage(image))
        self.graphics_scene.render(painter)
        self.graphics_item.setPixmap(QPixmap())
        return result


def getOpenFileName(*, parent, title, filter="", config: 'SimpleConfig') -> Optional[str]:
    """Custom wrapper for getOpenFileName that remembers the path selected by the user."""
    directory = config.get('io_dir', os.path.expanduser('~'))
    fileName, __ = QFileDialog.getOpenFileName(parent, title, directory, filter)
    if fileName and directory != os.path.dirname(fileName):
        config.set_key('io_dir', os.path.dirname(fileName), True)
    return fileName

def getSaveFileName(
        *,
        parent,
        title,
        filename,
        filter="",
        default_extension: str = None,
        default_filter: str = None,
        config: 'SimpleConfig',
) -> Optional[str]:
    """Custom wrapper for getSaveFileName that remembers the path selected by the user."""
    directory = config.get('io_dir', os.path.expanduser('~'))
    path = os.path.join(directory, filename)

    file_dialog = QFileDialog(parent, title, path, filter)
    file_dialog.setAcceptMode(QFileDialog.AcceptSave)
    if default_extension:
        # note: on MacOS, the selected filter's first extension seems to have priority over this...
        file_dialog.setDefaultSuffix(default_extension)
    if default_filter:
        assert default_filter in filter, f"default_filter={default_filter!r} does not appear in filter={filter!r}"
        file_dialog.selectNameFilter(default_filter)
    if file_dialog.exec() != QDialog.Accepted:
        return None

    selected_path = file_dialog.selectedFiles()[0]
    if selected_path and directory != os.path.dirname(selected_path):
        config.set_key('io_dir', os.path.dirname(selected_path), True)
    return selected_path


if __name__ == "__main__":
    app = QApplication([])
    t = WaitingDialog(None, 'testing ...', lambda: [time.sleep(1)], lambda x: QMessageBox.information(None, 'done', "done"))
    t.start()
    app.exec_()
