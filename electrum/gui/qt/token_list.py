#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import datetime
import threading
from enum import IntEnum

from PyQt5.QtCore import (
    Qt, QModelIndex, QItemSelectionModel, QPersistentModelIndex, QPoint, QVariant, QAbstractItemModel)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont, QBrush, QColor
from PyQt5.QtWidgets import QAbstractItemView, QMenu, QHeaderView

from electrum.bitcoin import hash160_to_p2pkh, is_address
from electrum.wallet import InternalAddressCorruption
from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.util import block_explorer_URL, TxMinedInfo, OrderedDictWithIndex, profiler, timestamp_to_datetime
from .util import read_QIcon, MyTreeView, AcceptFileDragDrop, webopen, MONOSPACE_FONT, TX_ICONS
from electrum.logging import get_logger, Logger

from .history_list import HistorySortModel


class TokenBalanceList(MyTreeView):

    class Columns(IntEnum):
        NAME = 0
        BIND_ADDRESS = 1
        BALANCE = 2
        SYMBOL = 3

    filter_columns = [Columns.NAME, Columns.BIND_ADDRESS, Columns.BALANCE, Columns.SYMBOL]

    headers = {
        Columns.NAME: _('Name'),
        Columns.BIND_ADDRESS: _('Bind Address'),
        Columns.BALANCE: _('Balance'),
        Columns.SYMBOL: _('Symbol'),
    }

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.BIND_ADDRESS,
                         editable_columns=[])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.update()

    def update(self):
        current_key = self.current_item_user_role(self.Columns.NAME)
        self.model().clear()
        set_current = None
        self.update_headers(self.headers)
        for key in sorted(self.parent.wallet.db.list_tokens()):
            token = self.parent.wallet.db.get_token(key)
            balance_str = '{}'.format(token.balance / 10 ** token.decimals)
            labels = [token.name, token.bind_addr, balance_str, token.symbol]
            item = [QStandardItem(e) for e in labels]
            item[self.Columns.NAME].setData(token.contract_addr, Qt.UserRole)
            item[self.Columns.NAME].setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            item[self.Columns.BALANCE].setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            item[self.Columns.BALANCE].setFont(QFont(MONOSPACE_FONT))

            row_count = self.model().rowCount()
            self.model().insertRow(row_count, item)
            idx = self.model().index(row_count, self.Columns.NAME)
            if key == current_key:
                set_current = QPersistentModelIndex(idx)
        self.set_current_idx(set_current)
        self.filter()

    def mouseDoubleClickEvent(self, item):
        idx = self.indexAt(item.pos())
        if not idx.isValid():
            return
        try:
            bind_addr = self.model().itemFromIndex(self.selected_in_column(self.Columns.BIND_ADDRESS)[0]).text()
            contract_addr = self.model().itemFromIndex(self.selected_in_column(self.Columns.NAME)[0]).data(Qt.UserRole)
        except:
            return
        key = f'{contract_addr}_{bind_addr}'
        token = self.parent.wallet.db.get_token(key)
        self.parent.token_send_dialog(token)

    def create_menu(self, position: QPoint):
        menu = QMenu()
        selected = self.selected_in_column(self.Columns.NAME)
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Add Token"), lambda: self.parent.token_add_dialog())
        elif not multi_select:
            bind_addr = self.model().itemFromIndex(self.selected_in_column(self.Columns.BIND_ADDRESS)[0]).text()
            contract_addr = self.model().itemFromIndex(self.selected_in_column(self.Columns.NAME)[0]).data(
                Qt.UserRole)
            key = '{}_{}'.format(contract_addr, bind_addr)
            token = self.parent.wallet.db.get_token(key)
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            col = idx.column()
            column_title = self.model().horizontalHeaderItem(col).text()
            copy_text = self.model().itemFromIndex(idx).text()
            if col == self.Columns.BALANCE:
                copy_text = copy_text.strip()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(copy_text))
            menu.addAction(_("View Info"), lambda: self.parent.token_info_dialog(token))
            menu.addAction(_("Send"), lambda: self.parent.token_send_dialog(token))
            menu.addAction(_("Delete"), lambda: self.parent.delete_token(key))
            URL = block_explorer_URL(self.config, addr=bind_addr, token=contract_addr)
            if URL:
                menu.addAction(_("View on block explorer"), lambda: webopen(URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def place_text_on_clipboard(self, text):
        if is_address(text):
            try:
                self.parent.wallet.check_address_for_corruption(text)
            except InternalAddressCorruption as e:
                self.parent.show_error(str(e))
                raise
        super().place_text_on_clipboard(text)


class TokenHistoryColumns(IntEnum):
    STATUS = 0
    BIND_ADDRESS = 1
    TOKEN = 2
    AMOUNT = 3


class TokenHistoryModel(QAbstractItemModel, Logger):

    def __init__(self, parent: 'ElectrumWindow'):
        QAbstractItemModel.__init__(self, parent)
        Logger.__init__(self)
        self.parent = parent
        self.view = None  # type: TokenHistoryList
        self.transactions = OrderedDictWithIndex()
        self.tx_status_cache = {}  # type: Dict[str, Tuple[int, str]]

    def set_view(self, token_hist_list: 'TokenHistoryList'):
        # FIXME HistoryModel and HistoryList mutually depend on each other.
        # After constructing both, this method needs to be called.
        self.view = token_hist_list  # type: TokenHistoryList
        self.set_visibility_of_columns()

    def columnCount(self, parent: QModelIndex):
        return len(TokenHistoryColumns)

    def rowCount(self, parent: QModelIndex):
        return len(self.transactions)

    def index(self, row: int, column: int, parent: QModelIndex):
        return self.createIndex(row, column)

    def data(self, index: QModelIndex, role: Qt.ItemDataRole) -> QVariant:
        # note: this method is performance-critical.
        # it is called a lot, and so must run extremely fast.
        assert index.isValid()
        col = index.column()
        tx_item = self.transactions.value_from_pos(index.row())
        if not tx_item:
            return QVariant()
        tx_hash = tx_item['txid']
        conf = tx_item['confirmations']
        txpos = tx_item['txpos_in_block'] or 0
        height = tx_item['height']
        token = self.parent.wallet.db.get_token(tx_item['token_key'])
        bind_addr = tx_item['bind_addr']
        from_addr = tx_item['from_addr']
        to_addr = tx_item['to_addr']

        timestamp = tx_item['timestamp']
        if timestamp is None:
            timestamp = float("inf")

        try:
            status, status_str = self.tx_status_cache[tx_hash]
        except KeyError:
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            status, status_str = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)

        balance_str = f"{tx_item['amount']}" if to_addr == bind_addr else f"- {tx_item['amount']}"

        if role == Qt.UserRole:
            # for sorting
            d = {
                TokenHistoryColumns.STATUS: (-timestamp, conf, -status, -height, -txpos),
                TokenHistoryColumns.BIND_ADDRESS: bind_addr,
                TokenHistoryColumns.TOKEN: token.symbol,
                TokenHistoryColumns.AMOUNT: balance_str,
            }
            return QVariant(d[col])

        if role not in (Qt.DisplayRole, Qt.EditRole):
            if col == TokenHistoryColumns.STATUS and role == Qt.DecorationRole:
                return QVariant(read_QIcon(TX_ICONS[status]))
            elif col == TokenHistoryColumns.STATUS and role == Qt.ToolTipRole:
                return QVariant(str(conf) + _(" confirmation" + ("s" if conf != 1 else "")))
            elif col > TokenHistoryColumns.BIND_ADDRESS and role == Qt.TextAlignmentRole:
                return QVariant(int(Qt.AlignRight | Qt.AlignVCenter))
            elif col != TokenHistoryColumns.STATUS and role == Qt.FontRole:
                return QVariant(QFont(MONOSPACE_FONT))
            elif col in (TokenHistoryColumns.TOKEN, TokenHistoryColumns.AMOUNT) \
                    and role == Qt.ForegroundRole and from_addr == bind_addr:
                red_brush = QBrush(QColor("#BC1E1E"))
                return QVariant(red_brush)
            return QVariant()
        if col == TokenHistoryColumns.STATUS:
            return QVariant(status_str)
        elif col == TokenHistoryColumns.BIND_ADDRESS:
            return QVariant(bind_addr)
        elif col == TokenHistoryColumns.TOKEN:
            return QVariant(token.symbol)
        elif col == TokenHistoryColumns.AMOUNT:
            amount = tx_item['amount']
            if from_addr == bind_addr:
                amount = -amount
            v_str = self.parent.format_amount(amount, is_diff=True, whitespaces=True, num_zeros=0, decimal_point=token.decimals)
            return QVariant(v_str)
        return QVariant()

    def parent(self, index: QModelIndex):
        return QModelIndex()

    def hasChildren(self, index: QModelIndex):
        return not index.isValid()

    @profiler
    def refresh(self, reason: str):
        self.logger.info(f"token refreshing... reason: {reason}")
        assert self.parent.gui_thread == threading.current_thread(), 'must be called from GUI thread'
        assert self.view, 'view not set'
        selected = self.view.selectionModel().currentIndex()
        selected_row = None
        if selected:
            selected_row = selected.row()
        self.set_visibility_of_columns()

        hist = self.parent.wallet.get_full_token_history()
        if hist == list(self.transactions.values()):
            return
        old_length = len(self.transactions)
        if old_length != 0:
            self.beginRemoveRows(QModelIndex(), 0, old_length)
            self.transactions.clear()
            self.endRemoveRows()
        self.beginInsertRows(QModelIndex(), 0, len(hist)-1)
        for tx_item in hist:
            txid = tx_item['bind_addr'] + "_" + tx_item['txid']
            self.transactions[txid] = tx_item
        self.endInsertRows()
        if selected_row:
            self.view.selectionModel().select(self.createIndex(selected_row, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        # update tx_status_cache
        self.tx_status_cache.clear()
        for txid, tx_item in self.transactions.items():
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            self.tx_status_cache[txid] = self.parent.wallet.get_tx_status(txid, tx_mined_info)

    def set_visibility_of_columns(self):
        def set_visible(col: int, b: bool):
            self.view.showColumn(col) if b else self.view.hideColumn(col)
        # set_visible(TokenHistoryColumns.TXID, False)

    def update_tx_mined_status(self, tx_hash: str, tx_mined_info: TxMinedInfo):
        try:
            row = self.transactions.pos_from_key(tx_hash)
            tx_item = self.transactions[tx_hash]
        except KeyError:
            return
        self.tx_status_cache[tx_hash] = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)
        tx_item.update({
            'confirmations':  tx_mined_info.conf,
            'timestamp':      tx_mined_info.timestamp,
            'txpos_in_block': tx_mined_info.txpos,
            'date':           timestamp_to_datetime(tx_mined_info.timestamp),
        })
        topLeft = self.createIndex(row, 0)
        bottomRight = self.createIndex(row, len(TokenHistoryColumns) - 1)
        self.dataChanged.emit(topLeft, bottomRight)

    def headerData(self, section: int, orientation: Qt.Orientation, role: Qt.ItemDataRole):
        assert orientation == Qt.Horizontal
        if role != Qt.DisplayRole:
            return None
        return {
            TokenHistoryColumns.STATUS: _('Date'),
            TokenHistoryColumns.BIND_ADDRESS: _('Bind Address'),
            TokenHistoryColumns.TOKEN: _('Token'),
            TokenHistoryColumns.AMOUNT: _('Amount'),
        }[section]

    def flags(self, idx):
        extra_flags = Qt.NoItemFlags # type: Qt.ItemFlag
        if idx.column() in self.view.editable_columns:
            extra_flags |= Qt.ItemIsEditable
        return super().flags(idx) | int(extra_flags)

    @staticmethod
    def tx_mined_info_from_tx_item(tx_item):
        tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                    conf=tx_item['confirmations'],
                                    timestamp=tx_item['timestamp'])
        return tx_mined_info


class TokenHistoryList(MyTreeView):
    filter_columns = [TokenHistoryColumns.STATUS,
                      TokenHistoryColumns.BIND_ADDRESS,
                      TokenHistoryColumns.TOKEN,
                      TokenHistoryColumns.AMOUNT]

    def tx_item_from_proxy_row(self, proxy_row):
        thm_idx = self.model().mapToSource(self.model().index(proxy_row, 0))
        return self.thm.transactions.value_from_pos(thm_idx.row())

    def __init__(self, parent, model: TokenHistoryModel):
        super().__init__(parent, self.create_menu, stretch_column=TokenHistoryColumns.BIND_ADDRESS)
        self.thm = model
        self.proxy = HistorySortModel(self)
        self.proxy.setSourceModel(model)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.wallet = self.parent.wallet  # type: Abstract_Wallet
        self.sortByColumn(TokenHistoryColumns.STATUS, Qt.AscendingOrder)

        self.header().setStretchLastSection(False)
        for col in TokenHistoryColumns:
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def mouseDoubleClickEvent(self, event):
        idx = self.indexAt(event.pos())
        if not idx.isValid():
            return
        tx_item = self.tx_item_from_proxy_row(idx.row())
        self.show_transaction(tx_item['txid'])

    def show_transaction(self, txid):
        tx = self.wallet.db.get_token_tx(txid)
        if not tx:
            return
        self.parent.show_transaction(tx, tx_desc=None)

    def create_menu(self, position: QPoint):
        org_idx: QModelIndex = self.indexAt(position)
        idx = self.proxy.mapToSource(org_idx)
        if not idx.isValid():
            # can happen e.g. before list is populated for the first time
            return
        tx_item = self.thm.transactions.value_from_pos(idx.row())
        column = idx.column()
        column_title = self.thm.headerData(column, Qt.Horizontal, Qt.DisplayRole)
        column_data = self.thm.data(idx, Qt.DisplayRole).value()
        tx_hash = tx_item['txid']
        tx = self.wallet.db.get_token_tx(tx_hash)
        if not tx:
            return
        tx_URL = block_explorer_URL(self.config, tx=tx_hash)
        menu = QMenu()
        if column is TokenHistoryColumns.AMOUNT:
            column_data = column_data.strip()
        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        menu.addAction(_("Details"), lambda: self.show_transaction(tx_hash))

        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webopen(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))
