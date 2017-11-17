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

from .util import ButtonsLineEdit, Buttons, ButtonsTextEdit, CancelButton
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
            return
        address = self.address_e.text()
        if not is_hash160(address):
            return
        name = self.name_e.text()
        if not name:
            return
        self.contract['interface'] = interface
        self.contract['address'] = address
        self.contract['name'] = name
        self.callback(self.contract)


class ContractCreateDialog(QDialog):
    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Create Smart Contract'))
        self.setMinimumSize(700, 400)
        self.main_window = parent
        run_hook('contract_create_dialog', self)


class ContractEditDialog(QDialog):
    def __init__(self, parent, contract=None):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Subscribe Smart Contract'))
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



class ContractCallDialog(QDialog):
    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Call Smart Contract'))
        self.setMinimumSize(700, 400)
        self.main_window = parent
        run_hook('contract_call_dialog', self)
