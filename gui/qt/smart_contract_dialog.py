#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import json
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

from .util import ButtonsLineEdit, Buttons, ButtonsTextEdit, CancelButton, MessageBoxMixin, EnterButton
from qtum_electrum.i18n import _
from qtum_electrum.plugins import run_hook
from qtum_electrum.qtum import is_hash160, is_address, b58_address_to_hash160
from qtum_electrum.util import bh2u, print_error

float_validator = QRegExpValidator(QRegExp('^(-?\d+)(\.\d+)?$'))
int_validator = QIntValidator(0, 10 ** 9 - 1)


class ContractInfoLayout(QVBoxLayout):
    def __init__(self, dialog, contract, callback):
        QVBoxLayout.__init__(self)
        if not contract:
            contract = {
                'name': '',
                'interface': '',
                'address': ''
            }
        self.contract = contract
        self.callback = callback
        self.dialog = dialog

        self.addWidget(QLabel(_("Contract Name:")))
        self.name_e = ButtonsLineEdit()
        self.addWidget(self.name_e)

        self.addWidget(QLabel(_("Address:")))
        self.address_e = ButtonsLineEdit()
        self.addWidget(self.address_e)

        self.addWidget(QLabel(_("Interface(ABI):")))
        self.interface_e = ButtonsTextEdit()
        self.interface_e.setMinimumHeight(160)
        self.addWidget(self.interface_e)

        self.cancel_btn = CancelButton(dialog)
        self.save_btn = QPushButton(_('Save'))
        self.save_btn.setDefault(True)
        self.save_btn.clicked.connect(self.save_input)

        self.addLayout(Buttons(*[self.cancel_btn, self.save_btn]))
        self.update()

    def update(self):
        name = self.contract.get('name', '')
        address = self.contract.get('address', '')
        interface = self.contract.get('interface', '')
        if isinstance(interface, list):
            interface = json.dumps(interface)
        self.name_e.setText(name)
        self.interface_e.setText(interface)
        self.address_e.setText(address)

    def save_input(self):
        interface_text = self.interface_e.text()
        try:
            interface = json.loads(interface_text)
        except json.JSONDecodeError as e:
            self.dialog.show_message(_('invalid interface') + ' {}'.format(e))
            return
        address = self.address_e.text()
        address = address.rstrip().lstrip()
        if not is_hash160(address):
            self.dialog.show_message(_('invalid contract address'))
            return
        name = self.name_e.text()
        name = name.rstrip().lstrip()
        if len(name) > 10:
            self.dialog.show_message(_('name too long'))
            return
        if not name:
            self.dialog.show_message(_('empty name not allowed'))
            return
        self.contract['interface'] = interface
        self.contract['address'] = address
        self.contract['name'] = name
        self.callback(self.contract)


class ContractEditDialog(QDialog, MessageBoxMixin):
    def __init__(self, parent, contract=None):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Smart Contract'))
        self.setMinimumSize(700, 400)
        self.main_window = parent
        run_hook('contract_edit_dialog', self)
        layout = ContractInfoLayout(self, contract, callback=self.save)
        self.setLayout(layout)

    def save(self, contract):
        if self.parent().set_smart_contract(contract['name'],
                                            contract['address'],
                                            contract['interface']):
            self.accept()


class ContractFuncLayout(QGridLayout):
    def __init__(self, dialog, contract):
        QGridLayout.__init__(self)
        self.setSpacing(8)
        self.setColumnStretch(3, 1)
        self.dialog = dialog
        self.contract = contract
        self.senders = self.dialog.parent().wallet.get_spendable_addresses()

        address_lb = QLabel(_("Address:"))
        self.address_e = ButtonsLineEdit()
        qr_show = lambda: dialog.parent().show_qrcode(str(self.address_e.text()), 'Address', parent=dialog)
        self.address_e.addButton(":icons/qrcode.png", qr_show, _("Show as QR code"))
        self.address_e.setText(self.contract['address'])
        self.address_e.setReadOnly(True)
        self.addWidget(address_lb, 1, 0)
        self.addWidget(self.address_e, 1, 1, 1, -1)

        abi_lb = QLabel(_('Function:'))
        self.abi_combo = QComboBox()

        self.abi_signatures = [(-1, "(00)"), ]
        for index, abi in enumerate(contract.get('interface', [])):
            if not abi.get('type') == 'function':
                continue
            signature = '{}({})'.format(
                abi.get('name', ''),
                ', '.join(['{} {}'.format(i.get('type'), i.get('name')) for i in abi.get('inputs', [])]))
            self.abi_signatures.append((index, signature))

        self.abi_combo.addItems([s[1] for s in self.abi_signatures])
        self.abi_combo.setFixedWidth(self.address_e.width())
        if len(self.senders) > 0:
            self.abi_combo.setCurrentIndex(0)
        self.addWidget(abi_lb, 2, 0)
        self.addWidget(self.abi_combo, 2, 1, 1, -1)
        self.abi_combo.currentIndexChanged.connect(self.update)

        args_lb = QLabel(_('Parameters:'))
        self.args_e = QLineEdit()
        self.addWidget(args_lb, 3, 0)
        self.addWidget(self.args_e, 3, 1, 1, -1)

        self.optional_lb = QLabel(_('Optional:'))
        self.addWidget(self.optional_lb, 4, 0)
        self.optional_widget = QWidget()

        optional_layout = QHBoxLayout()
        optional_layout.setContentsMargins(0, 0, 0, 0)
        optional_layout.setSpacing(0)

        gas_limit_lb = QLabel(_('gas limit: '))
        self.gas_limit_e = ButtonsLineEdit()
        self.gas_limit_e.setValidator(int_validator)
        self.gas_limit_e.setText('250000')
        gas_price_lb = QLabel(_('gas price: '))
        self.gas_price_e = ButtonsLineEdit()
        self.gas_price_e.setValidator(float_validator)
        self.gas_price_e.setText('0.00000040')
        amount_lb = QLabel(_('amount: '))
        self.amount_e = ButtonsLineEdit()
        self.amount_e.setValidator(float_validator)
        optional_layout.addWidget(gas_limit_lb)
        optional_layout.addWidget(self.gas_limit_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(gas_price_lb)
        optional_layout.addWidget(self.gas_price_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(amount_lb)
        optional_layout.addWidget(self.amount_e)
        optional_layout.addStretch(0)
        self.optional_widget.setLayout(optional_layout)
        self.addWidget(self.optional_widget, 4, 1, 1, -1)

        sender_lb = QLabel(_('Sender:'))
        self.addWidget(sender_lb, 5, 0)

        buttons = QHBoxLayout()
        self.sender_combo = QComboBox()
        self.sender_combo.setMinimumWidth(400)
        self.sender_combo.addItems(self.senders)
        buttons.addWidget(self.sender_combo)
        buttons.addStretch(1)
        self.call_button = EnterButton(_("Call"), self.do_call)
        self.sendto_button = EnterButton(_("Send to"), self.do_sendto)
        buttons.addWidget(self.call_button)
        buttons.addWidget(self.sendto_button)
        buttons.addStretch()
        self.addLayout(buttons, 5, 1, 1, -1)

        self.update()

    def update(self):
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        self.sendto_button.setHidden(True)
        self.call_button.setHidden(True)

        def show_call():
            self.optional_widget.setEnabled(False)
            self.call_button.setHidden(False)

        def show_sendto():
            self.optional_widget.setEnabled(True)
            self.sendto_button.setHidden(False)

        if abi_index == -1:
            show_sendto()
        else:
            abi = self.contract['interface'][abi_index]
            if not abi.get('stateMutability'):
                self.dialog.show_message('stateMutability not found')
            elif abi.get('stateMutability') == 'view':
                show_call()
            elif abi.get('stateMutability') == 'nonpayable':
                show_sendto()

    def parse_values(self):
        def parse_edit_value(edit, times=10 ** 8):
            try:
                return int(float(edit.text()) * times)
            except ValueError:
                return 0

        return parse_edit_value(self.gas_limit_e, 1), parse_edit_value(self.gas_price_e), parse_edit_value(
            self.amount_e)

    def parse_args(self):
        args = json.loads('[{}]'.format(self.args_e.text()))
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        if abi_index == -1:
            return None, []
        abi = self.contract['interface'][abi_index]
        inputs = abi.get('inputs', [])
        if not len(args) == len(inputs):
            raise Exception('invalid input count,expect {} got {}'.format(len(inputs), len(args)))
        for index, _input in enumerate(inputs):
            _type = _input.get('type', '')
            if _type == 'address':
                addr = args[index]
                if is_address(addr):
                    __, hash160 = b58_address_to_hash160(addr)
                    addr = bh2u(hash160)
                if not is_hash160(addr):
                    raise Exception('invalid input:{}'.format(args[index]))
                args[index] = addr.lower()
            elif 'int' in _type:
                if not isinstance(args[index], int):
                    raise Exception('inavlid input:{}'.format(args[index]))
        if len(self.senders) > 0:
            sender = self.senders[self.sender_combo.currentIndex()]
        else:
            sender = ''
        return abi, args, sender

    def do_call(self):
        try:
            abi, args, sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        self.dialog.do_call(abi, args, sender)

    def do_sendto(self):
        try:
            abi, args, sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        if not sender:
            self.dialog.show_message('no sender selected')
            return

        gas_limit, gas_price, amount = self.parse_values()
        self.dialog.do_sendto(abi, args, gas_limit, gas_price, amount, sender)


class ContractFuncDialog(QDialog, MessageBoxMixin):
    def __init__(self, parent, contract):
        QDialog.__init__(self, parent=parent)
        self.contract = contract
        self.setWindowTitle(contract['name'])
        self.setMinimumSize(700, 200)
        self.main_window = parent
        run_hook('contract_func_dialog', self)
        layout = ContractFuncLayout(self, contract)
        self.setLayout(layout)

    def do_call(self, abi, args, sender):
        address = self.contract['address']
        self.parent().call_smart_contract(address, abi, args, sender, self)

    def do_sendto(self, abi, ars, gas_limit, gas_price, amount, sender):
        address = self.contract['address']
        self.parent().sendto_smart_contract(address, abi, ars, gas_limit, gas_price, amount, sender, self)


class ContractCreateLayout(QVBoxLayout):
    def __init__(self, dialog):
        QVBoxLayout.__init__(self)
        self.dialog = dialog
        self.senders = self.dialog.parent().wallet.get_spendable_addresses()
        self.constructor = {}

        self.addWidget(QLabel(_("Bytecode:")))
        self.bytecode_e = ButtonsTextEdit()
        self.bytecode_e.setMinimumHeight(80)
        self.bytecode_e.setMaximumHeight(80)
        self.addWidget(self.bytecode_e)
        self.addStretch(1)

        self.addWidget(QLabel(_("Interface(ABI):")))
        self.interface_e = ButtonsTextEdit()
        self.interface_e.setMaximumHeight(80)
        self.interface_e.textChanged.connect(self.interface_changed)
        self.addWidget(self.interface_e)
        self.addStretch(1)

        params_layout = QHBoxLayout()
        args_lb = QLabel(_('Constructor:'))
        self.args_e = QLineEdit()
        params_layout.addWidget(args_lb)
        params_layout.addWidget(self.args_e)
        self.addLayout(params_layout)

        optional_layout = QHBoxLayout()
        self.addLayout(optional_layout)
        gas_limit_lb = QLabel(_('gas limit:'))
        self.gas_limit_e = ButtonsLineEdit()
        self.gas_limit_e.setValidator(int_validator)
        self.gas_limit_e.setText('2500000')
        gas_price_lb = QLabel(_('gas price:'))
        self.gas_price_e = ButtonsLineEdit()
        self.gas_price_e.setValidator(float_validator)
        self.gas_price_e.setText('0.00000040')
        sender_lb = QLabel(_('sender:'))
        self.sender_combo = QComboBox()
        self.sender_combo.setMinimumWidth(300)
        self.sender_combo.addItems(self.senders)
        optional_layout.addWidget(gas_limit_lb)
        optional_layout.addWidget(self.gas_limit_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(gas_price_lb)
        optional_layout.addWidget(self.gas_price_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(sender_lb)
        optional_layout.addWidget(self.sender_combo)

        self.cancel_btn = CancelButton(dialog)
        self.create_btn = QPushButton(_('Create'))
        self.create_btn.setDefault(True)
        self.create_btn.clicked.connect(self.create)
        self.addLayout(Buttons(*[self.cancel_btn, self.create_btn]))

    def parse_args(self):
        sender = None
        if len(self.senders) > 0:
            sender = self.senders[self.sender_combo.currentIndex()]
        if not sender:
            raise Exception('no sender selected')
        args = json.loads('[{}]'.format(self.args_e.text()))
        abi = self.constructor
        inputs = abi.get('inputs', [])
        if not len(args) == len(inputs):
            raise Exception('invalid input count,expect {} got {}'.format(len(inputs), len(args)))
        for index, _input in enumerate(inputs):
            _type = _input.get('type', '')
            if _type == 'address':
                addr = args[index]
                if is_address(addr):
                    __, hash160 = b58_address_to_hash160(addr)
                    addr = bh2u(hash160)
                if not is_hash160(addr):
                    raise Exception('invalid input:{}'.format(args[index]))
                args[index] = addr.lower()
            elif 'int' in _type:
                if not isinstance(args[index], int):
                    raise Exception('inavlid input:{}'.format(args[index]))
            elif _type == 'string' or _type == 'bytes':
                args[index] = args[index].encode()
        return abi, args, sender

    def parse_values(self):
        def parse_edit_value(edit, times=10 ** 8):
            try:
                return int(float(edit.text()) * times)
            except ValueError:
                return 0

        return parse_edit_value(self.gas_limit_e, 1), parse_edit_value(self.gas_price_e)

    def create(self):
        try:
            abi, args, sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        gas_limit, gas_price = self.parse_values()
        bytecode = self.bytecode_e.text()
        self.dialog.do_create(bytecode, abi, args, gas_limit, gas_price, sender)

    def interface_changed(self):
        interface_text = self.interface_e.text()
        try:
            interface = json.loads(interface_text)
            constructor = {}
            for abi in interface:
                if abi.get('type') == 'constructor':
                    constructor = abi
                    break
            self.constructor = constructor
            if not constructor:
                self.args_e.setPlaceholderText('')
                return
            signature = '{}'.format(', '.join(['{} {}'.format(i.get('type'), i.get('name'))
                                               for i in constructor.get('inputs', [])]))
            self.args_e.setPlaceholderText(signature)
        except (BaseException,) as e:
            self.constructor = {}
            self.args_e.setPlaceholderText('')
            print_error('[interface_changed]', str(e))


class ContractCreateDialog(QDialog, MessageBoxMixin):
    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Create Smart Contract'))
        self.setMinimumSize(700, 400)
        self.setMaximumSize(780, 500)
        self.main_window = parent
        run_hook('contract_create_dialog', self)
        layout = ContractCreateLayout(self)
        self.setLayout(layout)

    def do_create(self, bytecode, constructor, args, gas_limit, gas_price, sender):
        self.parent().create_smart_contract(bytecode, constructor, args, gas_limit, gas_price, sender, self)
