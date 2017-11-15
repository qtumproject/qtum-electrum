#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import webbrowser
from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.util import block_explorer_URL, format_satoshis, format_time, age
from electrum.plugins import run_hook
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (
    QAbstractItemView, QFileDialog, QMenu, QTreeWidgetItem)
from .util import MyTreeWidget


class SmartContractList(MyTreeWidget):
    filter_columns = [0, 1]  # Key, Value

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Name'), _('Address')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        return item.text(1) != "openalias"

    def on_edited(self, item, column, prior):
        pass
        # if column == 0:  # Remove old contact if renamed
        #     self.parent.contacts.pop(prior)
        # self.parent.set_contact(item.text(0), item.text(1))

    def create_contract(self):
        pass

    def subscribe_contract(self):
        pass
        # wallet_folder = self.parent.get_wallet_folder()
        # filename, __ = QFileDialog.getOpenFileName(self.parent, "Select your wallet file", wallet_folder)
        # if not filename:
        #     return
        # self.parent.contacts.import_file(filename)
        # self.on_update()

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Create contract"), lambda: self.parent.create_contract_dialog())
            menu.addAction(_("Subscribe contract"), lambda: self.parent.subscribe_contract_dialog())
        elif not multi_select:
            item = selected[0]
            name = item.text(0)
            key = item.text(1)
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy %s") % column_title, lambda: self.parent.app.clipboard().setText(column_data))
            if column in self.editable_columns:
                item = self.currentItem()
                menu.addAction(_("Edit %s") % column_title, lambda: self.editItem(item, column))
            menu.addAction(_("Call"), lambda: self.parent.call_contract_dialog(key))
            menu.addAction(_("Delete"), lambda: self.parent.delete_samart_contacts(key))
            URL = block_explorer_URL(self.config, 'addr', key)
            if URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(URL))
        run_hook('create_smart_contract_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_update(self):
        item = self.currentItem()
        current_key = item.data(0, Qt.UserRole) if item else None
        self.clear()
        for key in sorted(self.parent.contacts.keys()):
            _type, name = self.parent.contacts[key]
            item = QTreeWidgetItem([name, key])
            item.setData(0, Qt.UserRole, key)
            self.addTopLevelItem(item)
            if key == current_key:
                self.setCurrentItem(item)
        run_hook('update_smart_contract_tab', self)
