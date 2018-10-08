#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import random
import time
import threading
import base64
from functools import partial
import traceback
import sys
import json
import socket

import smtplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.encoders import encode_base64

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QLineEdit, QInputDialog, QPushButton)

from qtum_electrum.util import PrintError
from qtum_electrum.plugin import BasePlugin, hook
from qtum_electrum.paymentrequest import PaymentRequest
from qtum_electrum.i18n import _
from qtum_electrum.gui.qt.util import EnterButton, Buttons, CloseButton
from qtum_electrum.gui.qt.util import OkButton, WindowModalDialog, get_parent_main_window


class Processor(threading.Thread, PrintError):
    polling_interval = 1*60

    def __init__(self, smtp_server, username, password, callback):
        threading.Thread.__init__(self)
        self.daemon = True
        self.username = username
        self.password = password
        self.smtp_server = smtp_server
        self.on_receive = callback
        self.M = None
        self.reset_connect_wait()

    def reset_connect_wait(self):
        self.connect_wait = 100  # ms, between failed connection attempts

    def poll(self):
        self.M.select()
        typ, data = self.M.search(None, 'ALL')
        for num in str(data[0], 'utf8').split():
            typ, msg_data = self.M.fetch(num, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            p = msg.get_payload()
            if not msg.is_multipart():
                continue
            for item in p:
                if item.get_content_type() == "application/qtum-paymentrequest":
                    pr_str = item.get_payload()
                    pr_str = base64.b64decode(pr_str)
                    self.on_receive(pr_str)

    def run(self):
        while True:
            try:
                self.M = smtplib.SMTP_SSL(self.smtp_server, timeout=10)
                self.M.login(self.username, self.password)
            except BaseException as e:
                self.print_error('imap connecting failed: {}'.format(e))
                self.connect_wait *= 2
                time.sleep(random.randint(0, self.connect_wait))
                continue
            else:
                self.reset_connect_wait()
            # Reconnect when host changes
            while self.M:
                try:
                    self.poll()
                except BaseException as e:
                    self.print_error('polling failed: {}'.format(e))
                    break
                time.sleep(self.polling_interval)
            time.sleep(random.randint(0, self.connect_wait))

    def send(self, recipient, subject, part):
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['To'] = recipient
        msg['From'] = self.username
        msg.attach(part)
        s = smtplib.SMTP_SSL(self.smtp_server, timeout=5)
        s.login(self.username, self.password)
        s.sendmail(self.username, [recipient], msg.as_string())
        s.quit()


class QEmailSignalObject(QObject):
    email_new_invoice_signal = pyqtSignal()


class Plugin(BasePlugin):

    def fullname(self):
        return 'Email'

    def description(self):
        return _("Send and receive payment requests via email")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.smtp_server = self.config.get('email_smtp', '')
        self.username = self.config.get('email_username', '')
        self.password = self.config.get('email_password', '')
        if self.smtp_server and self.username and self.password:
            self.processor = Processor(self.smtp_server, self.username, self.password, self.on_receive)
            self.processor.start()
        self.obj = QEmailSignalObject()
        self.obj.email_new_invoice_signal.connect(self.new_invoice)
        self.wallets = set()

    def on_receive(self, pr_str):
        self.print_error('received payment request')
        self.pr = PaymentRequest(pr_str)
        self.obj.email_new_invoice_signal.emit()

    @hook
    def load_wallet(self, wallet, main_window):
        self.wallets |= {wallet}

    @hook
    def close_wallet(self, wallet):
        self.wallets -= {wallet}

    def new_invoice(self):
        for wallet in self.wallets:
            wallet.invoices.add(self.pr)
        #main_window.invoice_list.update()

    @hook
    def receive_list_menu(self, menu, addr):
        window = get_parent_main_window(menu)
        menu.addAction(_("Send via e-mail"), lambda: self.send(window, addr))

    def send(self, window, addr):
        from qtum_electrum import paymentrequest
        r = window.wallet.receive_requests.get(addr)
        subject = r.get('memo', '')
        if r.get('signature'):
            pr = paymentrequest.serialize_request(r)
        else:
            pr = paymentrequest.make_request(self.config, r)
        if not pr:
            return
        recipient, ok = QInputDialog.getText(window, 'Send request', 'Email invoice to:')
        if not ok:
            return
        recipient = str(recipient)
        payload = pr.SerializeToString()
        part = MIMEBase('application', "qtum-paymentrequest")
        part.set_payload(payload)
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="payreq.qtum"')
        self.print_error('sending mail to', recipient)
        try:
            self.processor.send(recipient, subject, part)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            window.show_message(str(e))
        else:
            window.show_message(_('Request sent.'))

    @hook
    def send_tx_layout(self, window, layout, tx):
        email_button = QPushButton(_("Email"))
        email_button.clicked.connect(lambda: self.send_tx(window, tx))
        layout.addWidget(email_button)

    def send_tx(self, window, tx):
        email_addr, ok = QInputDialog.getText(window, _('Send transaction'), _('Email to:'))
        if not ok:
            return
        email_addr = str(email_addr)
        subject = 'Qtum transactrion'

        payload = json.dumps(tx.as_dict(), indent=4) + '\n'
        part = MIMEBase('application', "qtum-transaction")
        part.set_payload(payload)
        encode_base64(part)

        name = 'signed_%s.txn' % (tx.txid()[0:8]) if tx.is_complete() else 'unsigned.txn'
        part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(name))

        try:
            self.processor.send(email_addr, subject, part)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            window.show_message(str(e))
        else:
            window.show_message(_('Request sent.'))

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Email settings"))
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_('Server hosting your email acount')))
        grid = QGridLayout()
        vbox.addLayout(grid)

        grid.addWidget(QLabel('Server (SMTP)'), 0, 0)
        server_s = QLineEdit()
        server_s.setText(self.smtp_server)
        grid.addWidget(server_s, 0, 1)

        grid.addWidget(QLabel('Username'), 1, 0)
        username_e = QLineEdit()
        username_e.setText(self.username)
        grid.addWidget(username_e, 1, 1)

        grid.addWidget(QLabel('Password'), 2, 0)
        password_e = QLineEdit()
        password_e.setText(self.password)
        grid.addWidget(password_e, 2, 1)

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        if not d.exec_():
            return

        smtp_server = str(server_s.text())
        self.config.set_key('email_smtp', smtp_server)
        self.smtp_server = smtp_server

        username = str(username_e.text())
        self.config.set_key('email_username', username)
        self.username = username

        password = str(password_e.text())
        self.config.set_key('email_password', password)
        self.password = password

        if self.smtp_server and self.username and self.password:
            check_connection = CheckConnectionThread(smtp_server, username, password, self.on_success)
            check_connection.connection_error_signal.connect(lambda e: window.show_message(
                _("Unable to connect to mail server:\n {}").format(e) + "\n" +
                _("Please check your connection and credentials.")
            ))
            check_connection.start()
        else:
            self.processor = None

    def on_success(self):
        self.processor = Processor(self.smtp_server, self.username, self.password, self.on_receive)
        self.processor.start()


class CheckConnectionThread(QThread):
    connection_error_signal = pyqtSignal(str)

    def __init__(self, server, username, password, callback):
        super().__init__()
        self.server = server
        self.username = username
        self.password = password
        self.callback = callback

    def run(self):
        try:
            conn = smtplib.SMTP_SSL(self.server, timeout=5)
            conn.login(self.username, self.password)
        except BaseException as e:
            self.connection_error_signal.emit(str(e))
            return
        self.callback()
