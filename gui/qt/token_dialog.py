#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from .util import ButtonsLineEdit, Buttons, ButtonsTextEdit, CancelButton, MessageBoxMixin, EnterButton
from qtum_electrum.qtum import is_hash160
from qtum_electrum.i18n import _
from qtum_electrum.tokens import Token


class TokenAddLayout(QGridLayout):
    def __init__(self, dialog, callback):
        """
        :type dialog: QDialog
        :type callback: func
        """
        QGridLayout.__init__(self)
        self.setSpacing(8)
        self.setColumnStretch(3, 1)
        self.callback = callback
        self.dialog = dialog
        self.addresses = self.dialog.parent().wallet.get_addresses()

        address_lb = QLabel(_("Contract Address:"))
        self.contract_addr_e = ButtonsLineEdit()
        self.addWidget(address_lb, 1, 0)
        self.addWidget(self.contract_addr_e, 1, 1, 1, -1)

        address_lb = QLabel(_("My Address:"))
        self.address_combo = QComboBox()
        self.address_combo.setMinimumWidth(300)
        self.address_combo.addItems(self.addresses)
        self.addWidget(address_lb, 2, 0)
        self.addWidget(self.address_combo, 2, 1, 1, -1)

        self.cancel_btn = CancelButton(dialog)
        self.save_btn = QPushButton(_('Save'))
        self.save_btn.setDefault(True)
        self.save_btn.clicked.connect(self.save_input)
        buttons = Buttons(*[self.cancel_btn, self.save_btn])
        buttons.addStretch()
        self.addLayout(buttons, 3, 2, 2, -1)

    def save_input(self):
        try:
            contract_addr = self.contract_addr_e.text()
            bind_addr = self.addresses[self.address_combo.currentIndex()]
            if not is_hash160(contract_addr):
                raise BaseException('invalid contrace address:{}'.format(contract_addr))
            token = Token(contract_addr, bind_addr, 'Test', 'T', 8, 10)
            self.callback(token)
            self.dialog.reject()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))


class TokenAddDialog(QDialog, MessageBoxMixin):

    def __init__(self, parent):
        """
        :type parent: ElectrumWindow
        :type token: Token
        """
        QDialog.__init__(self, parent=parent)
        self.main_window = parent
        self.setMinimumSize(500, 100)
        self.setWindowTitle(_('Add Token'))
        layout = TokenAddLayout(self, callback=self.save)
        self.setLayout(layout)

    def save(self, token):
        self.main_window.set_token(token)


class TokenInfoLayout(QGridLayout):
    def __init__(self, dialog, token):
        """
        :type dialog: QDialog
        :type token: Token
        :type callback: func
        """
        QGridLayout.__init__(self)
        self.setSpacing(8)
        self.setColumnStretch(3, 1)
        self.dialog = dialog
        self.addresses = self.dialog.parent().wallet.get_addresses()
        self.token = token

        address_lb = QLabel(_("Contract Address:"))
        self.contract_addr_e = ButtonsLineEdit()
        self.contract_addr_e.setReadOnly(True)
        self.addWidget(address_lb, 1, 0)
        self.addWidget(self.contract_addr_e, 1, 1, 1, -1)

        name_lb = QLabel(_('Token Name:'))
        self.name_e = QLineEdit()
        self.name_e.setReadOnly(True)
        self.addWidget(name_lb, 2, 0)
        self.addWidget(self.name_e, 2, 1, 1, -1)

        symbol_lb = QLabel(_('Token Symbol:'))
        self.symbol_e = QLineEdit()
        self.symbol_e.setReadOnly(True)
        self.addWidget(symbol_lb, 3, 0)
        self.addWidget(self.symbol_e, 3, 1, 1, -1)

        decimals_lb = QLabel(_('Decimals:'))
        self.decimals_e = QLineEdit()
        self.decimals_e.setReadOnly(True)
        self.addWidget(decimals_lb, 4, 0)
        self.addWidget(self.decimals_e, 4, 1, 1, -1)

        address_lb = QLabel(_("My Address:"))
        self.address_e = QLineEdit()
        self.address_e.setMinimumWidth(300)
        self.address_e.setReadOnly(True)
        self.addWidget(address_lb, 5, 0)
        self.addWidget(self.address_e, 5, 1, 1, -1)

        self.cancel_btn = CancelButton(dialog)
        buttons = Buttons(*[self.cancel_btn])
        buttons.addStretch()
        self.addLayout(buttons, 6, 2, 2, -1)

        self.update()

    def update(self):
        self.contract_addr_e.setText(self.token.contract_addr)
        self.address_e.setText(self.token.bind_addr)
        self.name_e.setText(self.token.name)
        self.symbol_e.setText(self.token.symbol)
        self.decimals_e.setText(str(self.token.decimals))


class TokenInfoDialog(QDialog, MessageBoxMixin):

    def __init__(self, parent, token):
        """
        :type parent: ElectrumWindow
        :type token: Token
        """
        QDialog.__init__(self, parent=parent)
        self.main_window = parent
        self.setMinimumSize(500, 200)
        self.setWindowTitle(_('View Token'))
        if not token:
            self.dialog.show_message("Empty Token")
            return
        layout = TokenInfoLayout(self, token)
        self.setLayout(layout)
