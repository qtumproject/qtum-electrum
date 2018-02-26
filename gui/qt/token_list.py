#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from .util import *


class TokenHistoryList(MyTreeWidget):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        self.refresh_headers()
        self.setColumnHidden(1, True)


class TokenBalanceList(MyTreeWidget):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        self.refresh_headers()
        self.setColumnHidden(1, True)
