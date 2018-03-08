#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from .util import *
from qtum_electrum.i18n import _
from qtum_electrum.plugins import run_hook
from qtum_electrum.util import block_explorer_URL, format_satoshis, open_browser


class TokenBalanceList(MyTreeWidget):
    filter_columns = [0, 1, 2]

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Name'), _('Bind Address'), _('Balance')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def on_update(self):
        item = self.currentItem()
        current_key = item.data(0, Qt.UserRole) if item else None
        self.clear()
        for key in sorted(self.parent.tokens.keys()):
            token = self.parent.tokens[key]
            balance_str = format_satoshis(token.balance, is_diff=False, num_zeros=0,
                                          decimal_point=token.decimals, whitespaces=True)
            item = QTreeWidgetItem([token.name, token.bind_addr, balance_str])
            item.setData(0, Qt.UserRole, token.contract_addr)
            item.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)
            item.setTextAlignment(2, Qt.AlignRight | Qt.AlignVCenter)
            item.setFont(2, QFont(MONOSPACE_FONT))
            self.addTopLevelItem(item)
            if key == current_key:
                self.setCurrentItem(item)
        run_hook('update_tokens_tab', self)

    def on_doubleclick(self, item, column):
        bind_addr = item.text(1)
        contract_addr = item.data(0, Qt.UserRole)
        key = '{}_{}'.format(contract_addr, bind_addr)
        token = self.parent.tokens.get(key, None)
        self.parent.token_send_dialog(token)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Add Token"), lambda: self.parent.token_add_dialog())
        elif not multi_select:
            item = selected[0]
            name = item.text(0)
            bind_addr = item.text(1)
            contract_addr = item.data(0, Qt.UserRole)
            key = '{}_{}'.format(contract_addr, bind_addr)
            token = self.parent.tokens.get(key, None)
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy %s") % column_title, lambda: self.parent.app.clipboard().setText(column_data))
            menu.addAction(_("View Info"), lambda: self.parent.token_view_dialog(token))
            menu.addAction(_("Send"), lambda: self.parent.token_send_dialog(token))
            menu.addAction(_("Delete"), lambda: self.parent.delete_token(key))
            URL = block_explorer_URL(self.config, {'addr': bind_addr, 'token': contract_addr})
            if URL:
                menu.addAction(_("View on block explorer"), lambda: open_browser(URL))
        run_hook('create_tokens_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))


class TokenHistoryList(MyTreeWidget):
    filter_columns = [0, 1, 2]

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, ["Name", "Date", "Address", "Amount"], 2)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
