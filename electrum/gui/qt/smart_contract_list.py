#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from enum import IntEnum

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import QPersistentModelIndex, Qt
from PyQt5.QtWidgets import QAbstractItemView, QMenu

from electrum.i18n import _
from electrum.util import block_explorer_URL
from electrum.bitcoin import is_address
from electrum.wallet import InternalAddressCorruption

from .util import MyTreeView, webopen


class SmartContractList(MyTreeView):

    class Columns(IntEnum):
        NAME = 0
        ADDRESS = 1

    filter_columns = [Columns.NAME, Columns.ADDRESS]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.ADDRESS)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.update()

    def mouseDoubleClickEvent(self, item):
        idx = self.indexAt(item.pos())
        if not idx.isValid():
            return
        try:
            address = self.model().itemFromIndex(self.selected_in_column(self.Columns.ADDRESS)[0]).text()
        except:
            return
        self.parent.contract_func_dialog(address)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selected_in_column(self.Columns.NAME)
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Add contract"), lambda: self.parent.contract_add_dialog())
            menu.addAction(_("Create contract"), lambda: self.parent.contract_create_dialog())
        elif not multi_select:
            address = self.model().itemFromIndex(self.selected_in_column(self.Columns.ADDRESS)[0]).text()
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            col = idx.column()
            column_title = self.model().horizontalHeaderItem(col).text()
            copy_text = self.model().itemFromIndex(idx).text()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(copy_text))
            menu.addAction(_("Edit"), lambda: self.parent.contract_edit_dialog(address))
            menu.addAction(_("Function"), lambda: self.parent.contract_func_dialog(address))
            menu.addAction(_("Delete"), lambda: self.parent.delete_samart_contact(address))
            URL = block_explorer_URL(self.config, token=address)
            if URL:
                menu.addAction(_("View on block explorer"), lambda: webopen(URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def update(self):
        current_key = self.current_item_user_role(self.Columns.NAME)
        self.model().clear()
        set_current = None
        headers = {
            self.Columns.NAME: _('Name'),
            self.Columns.ADDRESS: _('Address'),
        }
        self.update_headers(headers)
        for address in sorted(self.parent.wallet.db.smart_contracts.keys()):
            name, abi = self.parent.wallet.db.smart_contracts[address]
            labels = [name, address]
            item = [QStandardItem(e) for e in labels]
            item[self.Columns.NAME].setData(address, Qt.UserRole)
            row_count = self.model().rowCount()
            self.model().insertRow(row_count, item)
            idx = self.model().index(row_count, self.Columns.NAME)
            if address == current_key:
                set_current = QPersistentModelIndex(idx)
        self.set_current_idx(set_current)
        self.filter()

    def place_text_on_clipboard(self, text):
        if is_address(text):
            try:
                self.parent.wallet.check_address_for_corruption(text)
            except InternalAddressCorruption as e:
                self.parent.show_error(str(e))
                raise
        super().place_text_on_clipboard(text)
