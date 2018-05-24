#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
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
import datetime
from .util import *
from qtum_electrum.i18n import _
from qtum_electrum.util import block_explorer_URL, format_satoshis, format_time
from qtum_electrum.util import timestamp_to_datetime, profiler, open_browser
from qtum_electrum.wallet import TX_HEIGHT_LOCAL


class HistoryList(MyTreeWidget, AcceptFileDragDrop):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        AcceptFileDragDrop.__init__(self, ".txn")
        self.refresh_headers()
        self.setColumnHidden(1, True)
        self.start_timestamp = None
        self.end_timestamp = None
        self.years = []
        self.setSortingEnabled(True)
        self.create_toolbar_buttons()
        self.wallet = None

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def refresh_headers(self):
        headers = ['', '', _('Date'), _('Description'), _('Amount'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Amount'), '%s '%fx.ccy + _('Balance')])
        self.update_headers(headers)

    def get_domain(self):
        '''Replaced in address_dialog.py'''
        return self.wallet.get_addresses()

    def on_combo(self, x):
        s = self.period_combo.itemText(x)
        x = s == _('Custom')
        self.start_button.setEnabled(x)
        self.end_button.setEnabled(x)
        if s == _('All'):
            self.start_timestamp = None
            self.end_timestamp = None
            self.start_button.setText("-")
            self.end_button.setText("-")
        else:
            try:
                year = int(s)
            except:
                return
            start_date = datetime.datetime(year, 1, 1)
            end_date = datetime.datetime(year + 1, 1, 1)
            self.start_timestamp = time.mktime(start_date.timetuple())
            self.end_timestamp = time.mktime(end_date.timetuple())
            self.start_button.setText(_('From') + ' ' + self.format_date(start_date))
            self.end_button.setText(_('To') + ' ' + self.format_date(end_date))
        self.update()

    def create_toolbar_buttons(self):
        self.period_combo = QComboBox()
        self.start_button = QPushButton('-')
        self.start_button.setStyleSheet("border:1px groove white;border-radius:3px;padding:1px 15px;")
        self.start_button.pressed.connect(self.select_start_date)
        self.start_button.setEnabled(False)
        self.end_button = QPushButton('-')
        self.end_button.setStyleSheet("border:1px groove white;border-radius:3px;padding:1px 15px;")
        self.end_button.pressed.connect(self.select_end_date)
        self.end_button.setEnabled(False)
        self.period_combo.addItems([_('All'), _('Custom')])
        self.period_combo.activated.connect(self.on_combo)

    def get_toolbar_buttons(self):
        return self.period_combo, self.start_button, self.end_button

    def on_hide_toolbar(self):
        self.start_timestamp = None
        self.end_timestamp = None
        self.update()

    def select_start_date(self):
        self.start_timestamp = self.select_date(self.start_button)
        self.update()

    def select_end_date(self):
        self.end_timestamp = self.select_date(self.end_button)
        self.update()

    def select_date(self, button):
        d = WindowModalDialog(self, _("Select date"))
        d.setMinimumSize(600, 150)
        d.date = None
        vbox = QVBoxLayout()

        def on_date(date):
            d.date = date

        cal = QCalendarWidget()
        cal.setGridVisible(True)
        cal.clicked[QDate].connect(on_date)
        vbox.addWidget(cal)
        vbox.addLayout(Buttons(OkButton(d), CancelButton(d)))
        d.setLayout(vbox)
        if d.exec_():
            if d.date is None:
                return None
            date = d.date.toPyDate()
            button.setText(self.format_date(date))
            return time.mktime(date.timetuple())

    @profiler
    def on_update(self):
        self.wallet = self.parent.wallet
        h = self.wallet.get_history(self.get_domain(),
                                    from_timestamp=self.start_timestamp,
                                    to_timestamp=self.end_timestamp)
        if not self.years and h:
            from datetime import date
            if timestamp_to_datetime(h[0][3]):
                start_date = timestamp_to_datetime(h[0][3]).date()
            else:
                start_date = date.today()
            if timestamp_to_datetime(h[-1][3]):
                end_date = timestamp_to_datetime(h[-1][3]).date()
            else:
                end_date = date.today()

            self.years = [str(i) for i in range(start_date.year, end_date.year + 1)]
            self.period_combo.insertItems(1, self.years)

        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole) if item else None
        self.clear()
        fx = self.parent.fx
        if fx: fx.history_used_spot = False
        for h_item in h:
            tx_hash, height, conf, timestamp, value, balance = h_item

            status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
            has_invoice = self.wallet.invoices.paid.get(tx_hash)
            icon = self.icon_cache.get(":icons/" + TX_ICONS[status])
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label = self.wallet.get_label(tx_hash)
            if value and 0 < value < 4 * 10 ** 7 and label == 'stake mined':
                label = 'contract gas change'
            entry = ['', tx_hash, status_str, label, v_str, balance_str]
            if fx and fx.show_history():
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                for amount in [value, balance]:
                    text = fx.historical_value_str(amount, date)
                    entry.append(text)
            item = QTreeWidgetItem(entry)
            item.setIcon(0, icon)
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            if has_invoice:
                item.setIcon(3, self.icon_cache.get(":icons/seal"))
            for i in range(len(entry)):
                if i > 3:
                    item.setTextAlignment(i, Qt.AlignRight | Qt.AlignVCenter)
                if i != 2:
                    item.setFont(i, QFont(MONOSPACE_FONT))
            if value and value < 0:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
                item.setForeground(4, QBrush(QColor("#BC1E1E")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def on_doubleclick(self, item, column):
        tx_hash = item.data(0, Qt.UserRole)
        tx = self.wallet.transactions.get(tx_hash)
        self.parent.show_transaction(tx)

    def update_labels(self):
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            txid = item.data(0, Qt.UserRole)
            label = self.wallet.get_label(txid)
            item.setText(3, label)

    def update_item(self, tx_hash, height, conf, timestamp):
        if self.wallet is None:
            return
        status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
        icon = self.icon_cache.get(":icons/" + TX_ICONS[status])
        items = self.findItems(tx_hash, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setText(2, status_str)

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        column = self.currentColumn()
        tx_hash = item.data(0, Qt.UserRole)
        if not tx_hash:
            return
        if column is 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)

        tx_URL = block_explorer_URL(self.config, {'tx': tx_hash})
        height, conf, timestamp = self.wallet.get_tx_height(tx_hash)
        tx = self.wallet.transactions.get(tx_hash)
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        is_unconfirmed = height <= 0
        pr_key = self.wallet.invoices.paid.get(tx_hash)

        menu = QMenu()
        if height == TX_HEIGHT_LOCAL:
            menu.addAction(_("Remove"), lambda: self.remove_local_tx(tx_hash))

        menu.addAction(_("Copy %s")%column_title, lambda: self.parent.app.clipboard().setText(column_data))
        if column in self.editable_columns:
            menu.addAction(_("Edit %s")%column_title, lambda: self.editItem(item, column))

        menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))
        if is_unconfirmed and tx:
            # note: the current implementation of RBF *needs* the old tx fee
            rbf = is_mine and not tx.is_final() and fee is not None
            if rbf:
                menu.addAction(_("Increase fee"), lambda: self.parent.bump_fee_dialog(tx))
            else:
                child_tx = self.wallet.cpfp(tx, 0)
                if child_tx:
                    menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
        if pr_key:
            menu.addAction(self.icon_cache.get(":icons/seal"), _("View invoice"),
                           lambda: self.parent.show_invoice(pr_key))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: open_browser(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def remove_local_tx(self, delete_tx):
        to_delete = {delete_tx}
        to_delete |= self.wallet.get_depending_transactions(delete_tx)
        question = _("Are you sure you want to remove this transaction?")
        if len(to_delete) > 1:
            question = _(
                "Are you sure you want to remove this transaction and {} child transactions?".format(
                    len(to_delete) - 1)
            )
        answer = QMessageBox.question(self.parent, _("Please confirm"), question, QMessageBox.Yes, QMessageBox.No)
        if answer == QMessageBox.No:
            return
        for tx in to_delete:
            self.wallet.remove_transaction(tx)
        self.wallet.save_transactions(write=True)
        # need to update at least: history_list, utxo_list, address_list
        self.parent.need_update.set()

    def onFileAdded(self, fn):
        try:
            with open(fn) as f:
                tx = self.parent.tx_from_text(f.read())
                self.parent.save_transaction_into_wallet(tx)
        except (IOError, AssertionError) as e:
            self.parent.show_error(e)
