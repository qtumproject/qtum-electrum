#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from .util import *
from qtum_electrum.i18n import _
from qtum_electrum.plugins import run_hook
from qtum_electrum.util import block_explorer_URL, format_satoshis, format_time, open_browser


class TokenBalanceList(MyTreeWidget):
    filter_columns = [0, 1, 2]

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Name'), _('Bind Address'), _('Balance')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def on_update(self):
        pass

    def create_menu(self, position):
        pass

    def on_doubleclick(self, item, column):
        pass


class TokenHistoryList(MyTreeWidget):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, ["Name", "Address", "Amount"], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
