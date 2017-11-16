#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import webbrowser
from electrum.i18n import _
from electrum.qtum import is_address
from electrum.util import block_explorer_URL, format_satoshis, format_time, age
from electrum.plugins import run_hook
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QAbstractItemView, QMenu, QTreeWidgetItem
from .util import MyTreeWidget


class SmartContractList(MyTreeWidget):
    filter_columns = [0, 1]  # Key, Value

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Name'), _('Address')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Create contract"), lambda: self.parent.contract_create_dialog())
            menu.addAction(_("Subscribe contract"), lambda: self.parent.contract_subscribe_dialog())
        elif not multi_select:
            item = selected[0]
            name = item.text(0)
            address = item.text(1)
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy %s") % column_title, lambda: self.parent.app.clipboard().setText(column_data))
            menu.addAction(_("Edit"), lambda: self.parent.contract_edit_dialog(address))
            menu.addAction(_("Call"), lambda: self.parent.contract_call_dialog(address))
            menu.addAction(_("Delete"), lambda: self.parent.delete_samart_contact(address))
            URL = block_explorer_URL(self.config, 'contract', address)
            if URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(URL))
        run_hook('create_smart_contract_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_update(self):
        item = self.currentItem()
        current_key = item.data(0, Qt.UserRole) if item else None
        self.clear()
        for address in sorted(self.parent.smart_contracts.keys()):
            _type, name, abi = self.parent.smart_contracts[address]
            item = QTreeWidgetItem([name, address])
            item.setData(0, Qt.UserRole, address)
            self.addTopLevelItem(item)
            if address == current_key:
                self.setCurrentItem(item)
        run_hook('update_smart_contract_tab', self)
