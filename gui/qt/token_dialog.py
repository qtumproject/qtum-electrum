#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from .util import ButtonsLineEdit, Buttons, CancelButton, MessageBoxMixin
from .amountedit import AmountEdit
from qtum_electrum.qtum import is_hash160, is_b58_address, b58_address_to_hash160, bh2u, ADDRTYPE_P2PKH
from qtum_electrum.i18n import _
from qtum_electrum.tokens import Token
from qtum_electrum_plugins.trezor.trezor import TrezorKeyStore


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

        if isinstance(self.dialog.parent().wallet.keystore, TrezorKeyStore):
            self.dialog.show_message('Trezor does not support QRC20 Token for now')
            self.dialog.reject()
            return

        self.addresses = self.dialog.parent().wallet.get_addresses_sort_by_balance()

        addr_type, __ = b58_address_to_hash160(self.addresses[0])
        if not addr_type == ADDRTYPE_P2PKH:
            self.dialog.show_message('only P2PKH address supports QRC20 Token')
            self.dialog.reject()
            return

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
                raise Exception('invalid contrace address:{}'.format(contract_addr))
            self.callback(contract_addr, bind_addr)
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
        self.setMinimumSize(500, 100)
        self.setWindowTitle(_('Add Token'))
        layout = TokenAddLayout(self, callback=self.save)
        self.setLayout(layout)

    def save(self, contract_addr, bind_addr):
        try:
            r = self.parent().network.synchronous_get(('blockchain.token.get_info', [contract_addr]), timeout=10)
            name = r.get('name')
            decimals = r.get('decimals')
            symbol = r.get('symbol')
            if not name or not symbol or not decimals or not isinstance(decimals, int):
                self.show_message('token info not valid: {} {} {}'.format(name, symbol, decimals))
                return
            token = Token(contract_addr, bind_addr, name, symbol, decimals, 0)
            self.parent().set_token(token)
        except BaseException as e:
            self.show_message(str(e))


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
        self.setMinimumSize(500, 200)
        self.setWindowTitle(_('View Token'))
        if not token:
            self.dialog.show_message("Empty data")
            return
        layout = TokenInfoLayout(self, token)
        self.setLayout(layout)


class TokenSendLayout(QGridLayout):
    def __init__(self, dialog, token, callback):
        """
        :type dialog: QDialog
        :type token: Token
        :type callback: func
        """
        QGridLayout.__init__(self)
        self.setSpacing(8)
        self.setColumnStretch(3, 1)
        self.dialog = dialog
        self.token = token
        self.callback = callback

        address_lb = QLabel(_("My Address:"))
        self.address_e = QLineEdit()
        self.address_e.setMinimumWidth(300)
        self.address_e.setReadOnly(True)
        self.address_e.setText(token.bind_addr)
        self.addWidget(address_lb, 1, 0)
        self.addWidget(self.address_e, 1, 1, 1, -1)

        address_to_lb = QLabel(_("Pay to:"))
        self.address_to_e = QLineEdit()
        self.address_to_e.setMinimumWidth(300)
        self.addWidget(address_to_lb, 2, 0)
        self.addWidget(self.address_to_e, 2, 1, 1, -1)

        amount_lb = QLabel(_("Amount:"))
        self.amount_e = AmountEdit(lambda: self.token.symbol, False, None, self.token.decimals, 0)
        self.addWidget(amount_lb, 3, 0)
        self.addWidget(self.amount_e, 3, 1, 1, -1)

        optional_lb = QLabel(_('Optional:'))
        self.addWidget(optional_lb, 4, 0)
        optional_widget = QWidget()
        optional_layout = QHBoxLayout()
        optional_layout.setContentsMargins(0, 0, 0, 0)
        optional_layout.setSpacing(0)
        gas_limit_lb = QLabel(_('gas limit: '))
        self.gas_limit_e = AmountEdit(lambda: '', True, None, 0, 0)
        self.gas_limit_e.setText('250000')
        gas_price_lb = QLabel(_('gas price: '))
        self.gas_price_e = AmountEdit(lambda: '', False, None, 8, 0)
        self.gas_price_e.setText('0.00000040')
        optional_layout.addWidget(gas_limit_lb)
        optional_layout.addWidget(self.gas_limit_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(gas_price_lb)
        optional_layout.addWidget(self.gas_price_e)
        optional_layout.addStretch(0)
        optional_widget.setLayout(optional_layout)
        self.addWidget(optional_widget, 4, 1, 1, -1)

        self.cancel_btn = CancelButton(dialog)
        self.send_btn = QPushButton(_('Send'))
        self.send_btn.setDefault(True)
        self.send_btn.clicked.connect(self.send)
        buttons = Buttons(*[self.cancel_btn, self.send_btn])
        buttons.addStretch()
        self.addLayout(buttons, 5, 2, 2, -1)

    def parse_values(self):
        def parse_edit_value(edit, times=10 ** 8):
            return int(edit.get_amount() * times)

        return parse_edit_value(self.gas_limit_e, 1), parse_edit_value(self.gas_price_e), parse_edit_value(
            self.amount_e, 10 ** self.token.decimals)

    def send(self):
        try:
            gas_limit, gas_price, amount = self.parse_values()
        except (BaseException,) as e:
            self.dialog.show_message(e)
            return
        if self.token.balance < amount:
            self.dialog.show_message('token not enough')
            return
        address_to = self.address_to_e.text().rstrip().lstrip()
        if is_b58_address(address_to):
            addr_type, hash160 = b58_address_to_hash160(address_to)
            if addr_type == ADDRTYPE_P2PKH:
                hash160 = bh2u(hash160)
            else:
                self.dialog.show_message('invalid address')
                return
        elif is_hash160(address_to):
            hash160 = address_to.lower()
        else:
            self.dialog.show_message('invalid address')
            return
        self.callback(hash160, amount, gas_limit, gas_price)


class TokenSendDialog(QDialog, MessageBoxMixin):

    def __init__(self, parent, token):
        """
        :type parent: ElectrumWindow
        :type token: Token
        """
        QDialog.__init__(self, parent=parent)
        self.token = token
        self.setMinimumSize(500, 200)
        if not token:
            self.dialog.show_message("Empty data")
            return
        self.setWindowTitle(_('Send') + " " + token.name)
        layout = TokenSendLayout(self, token, self.do_send)
        self.setLayout(layout)

    def do_send(self, pay_to, amount, gas_limit, gas_price):
        self.parent().do_token_pay(self.token, pay_to, amount, gas_limit, gas_price, self)
