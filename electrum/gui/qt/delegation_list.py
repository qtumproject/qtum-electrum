#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""

from enum import IntEnum

from PyQt5.QtCore import Qt, QPersistentModelIndex, QPoint
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu

from electrum.i18n import _
from electrum.util import profiler
from electrum.bitcoin import is_address
from electrum.wallet import InternalAddressCorruption

from .util import MyTreeView, MONOSPACE_FONT


class DelegationList(MyTreeView):

    class Columns(IntEnum):
        ADDRESS = 0
        STAKER = 1
        FEE = 2
        BALANCE = 3

    filter_columns = [Columns.ADDRESS, Columns.STAKER, Columns.BALANCE, Columns.FEE]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.ADDRESS)
        self.wallet = self.parent.wallet
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))

    def get_toolbar_buttons(self):
        return []

    def refresh_headers(self):
        headers = {
            self.Columns.ADDRESS: _('Address'),
            self.Columns.STAKER: _('Staker'),
            self.Columns.FEE: _('Fee'),
            self.Columns.BALANCE: _('Balance'),
        }
        self.update_headers(headers)

    @profiler
    def update(self):
        if self.maybe_defer_update():
            return
        current_address = self.current_item_user_role(col=self.Columns.ADDRESS)
        self.model().clear()
        self.refresh_headers()
        set_address = None
        for addr in sorted(self.parent.wallet.db.list_delegations()):
            dele = self.parent.wallet.db.get_delegation(addr)
            c, u, x = self.wallet.get_addr_balance(addr)
            balance = c + u + x
            balance_text = self.parent.format_amount(balance, whitespaces=True)
            fee_text = f'{dele.fee}%'
            labels = [dele.addr, dele.staker, fee_text, balance_text]
            item = [QStandardItem(e) for e in labels]
            item[self.Columns.ADDRESS].setData(dele.addr, Qt.UserRole)
            item[self.Columns.ADDRESS].setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            item[self.Columns.BALANCE].setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            item[self.Columns.BALANCE].setFont(QFont(MONOSPACE_FONT))
            row_count = self.model().rowCount()
            self.model().insertRow(row_count, item)
            idx = self.model().index(row_count, self.Columns.ADDRESS)
            if addr == current_address:
                set_address = QPersistentModelIndex(idx)
        self.set_current_idx(set_address)

    def mouseDoubleClickEvent(self, item):
        idx = self.indexAt(item.pos())
        if not idx.isValid():
            return
        try:
            addr = self.model().itemFromIndex(self.selected_in_column(self.Columns.ADDRESS)[0]).text()
        except:
            return
        dele = self.parent.wallet.db.get_delegation(addr)
        self.parent.delegation_dialog(dele, mode='edit')

    def create_menu(self, position: QPoint):
        menu = QMenu()
        selected = self.selected_in_column(self.Columns.ADDRESS)
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Add Delegation"), lambda: self.parent.delegation_dialog())
        elif not multi_select:
            addr = self.model().itemFromIndex(self.selected_in_column(self.Columns.ADDRESS)[0]).text()
            dele = self.parent.wallet.db.get_delegation(addr)
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            col = idx.column()
            column_title = self.model().horizontalHeaderItem(col).text()
            copy_text = self.model().itemFromIndex(idx).text()
            if col == self.Columns.BALANCE:
                copy_text = copy_text.strip()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(copy_text))
            menu.addAction(_("Edit"), lambda: self.parent.delegation_dialog(dele, mode='edit'))
            if dele and dele.staker:
                menu.addAction(_("Undelegate"), lambda: self.parent.delegation_dialog(dele, mode='undelegate'))
        menu.exec_(self.viewport().mapToGlobal(position))

    def place_text_on_clipboard(self, text: str, *, title: str = None) -> None:
        if is_address(text):
            try:
                self.parent.wallet.check_address_for_corruption(text)
            except InternalAddressCorruption as e:
                self.parent.show_error(str(e))
                raise
        super().place_text_on_clipboard(text, title=title)