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
from electrum.i18n import _
from electrum.plugins import run_hook
from electrum.qtum import is_hash160


class ContractInfoLayout(QVBoxLayout):
    def __init__(self, dialog, contract, callback):
        QVBoxLayout.__init__(self)
        if not contract:
            contract = {
                'name': '',
                'type': 'contract',
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
        _type = self.contract.get('type', 'contract')
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
        except json.JSONDecodeError:
            self.dialog.show_message(_('invalid interface'))
            return
        address = self.address_e.text()
        if not is_hash160(address):
            self.dialog.show_message(_('invalid address'))
            return
        name = self.name_e.text()
        if not name:
            self.dialog.show_message(_('empty name'))
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
                                            contract['interface'],
                                            contract['type']):
            self.accept()


class ContractCallLayout(QGridLayout):
    def __init__(self, dialog, contract):
        QGridLayout.__init__(self)
        self.setSpacing(8)
        self.setColumnStretch(3, 1)
        self.dialog = dialog
        self.contract = contract

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
        self.abi_combo.setCurrentIndex(0)
        self.addWidget(abi_lb, 2, 0)
        self.addWidget(self.abi_combo, 2, 1, 1, -1)
        self.abi_combo.currentIndexChanged.connect(self.update)

        args_lb = QLabel(_('Parameters:'))
        self.args_e = QLineEdit()
        self.addWidget(args_lb, 3, 0)
        self.addWidget(self.args_e, 3, 1, 1, -1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.call_button = EnterButton(_("Call"), self.do_call)
        self.sendto_button = EnterButton(_("Send to"), self.do_sendto)
        buttons.addWidget(self.call_button)
        buttons.addWidget(self.sendto_button)
        self.addLayout(buttons, 4, 1, 1, -1)

        self.update()

    def update(self):
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        self.sendto_button.setHidden(True)
        self.call_button.setHidden(True)

        def show_call():
            pass

        def show_sendto():
            pass

        if abi_index == -1:
            show_sendto()
        else:
            abi = self.contract['interface'][abi_index]
            if abi['stateMutability'] == 'view':
                show_call()
            elif abi['stateMutability'] == 'nonpayable':
                show_sendto()

    def do_call(self):
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        abi = self.contract['interface'][abi_index]

    def do_sendto(self):
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        if abi_index == -1:
            pass
        else:
            abi = self.contract['interface'][abi_index]


class ContractCallDialog(QDialog):
    def __init__(self, parent, contract):
        QDialog.__init__(self, parent=parent)
        self.contract = contract
        self.setWindowTitle(contract['name'])
        self.setMinimumSize(700, 200)
        self.main_window = parent
        run_hook('contract_call_dialog', self)
        layout = ContractCallLayout(self, contract)
        self.setLayout(layout)


class ContractCreateDialog(QDialog):
    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Create Smart Contract'))
        self.setMinimumSize(700, 400)
        self.main_window = parent
        run_hook('contract_create_dialog', self)
