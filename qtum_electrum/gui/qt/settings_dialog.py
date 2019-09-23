#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from PyQt5.QtGui import QPixmap, QKeySequence, QIcon, QCursor
from PyQt5.QtCore import Qt, QRect, QStringListModel, QSize, pyqtSignal
from PyQt5.QtWidgets import (QMessageBox, QComboBox, QSystemTrayIcon, QTabWidget,
                             QSpinBox, QMenuBar, QFileDialog, QCheckBox, QLabel,
                             QVBoxLayout, QGridLayout, QLineEdit, QTreeWidgetItem,
                             QHBoxLayout, QPushButton, QScrollArea, QTextEdit,
                             QShortcut, QMainWindow, QCompleter, QInputDialog,
                             QWidget, QMenu, QSizePolicy, QStatusBar)
from .util import (read_QIcon, text_dialog, icon_path, WaitingDialog,
                   WindowModalDialog, ChoicesLayout, HelpLabel, Buttons,
                   OkButton, InfoButton, WWLabel, TaskThread, CancelButton,
                   CloseButton, HelpButton, MessageBoxMixin, EnterButton,
                   ButtonsLineEdit, CopyCloseButton, import_meta_gui, export_meta_gui,
                   filename_field, address_field, GREEN_BG, RED_BG)

from qtum_electrum import util, coinchooser, paymentrequest
from qtum_electrum.i18n import _

class SettingsDialog(WindowModalDialog):

    def __init__(self, parent, config):
        WindowModalDialog.__init__(self, parent, _('Preferences'))
        self.config = config
        self.window = parent
        self.need_restart = False
        self.fx = self.window.fx
        self.wallet = self.window.wallet

        vbox = QVBoxLayout()
        tabs = QTabWidget()
        gui_widgets = []
        fee_widgets = []
        tx_widgets = []
        id_widgets = []

        # language
        lang_help = _('Select which language is used in the GUI (after restart).')
        lang_label = HelpLabel(_('Language') + ':', lang_help)
        lang_combo = QComboBox()
        from qtum_electrum.i18n import languages
        lang_combo.addItems(list(languages.values()))
        lang_keys = list(languages.keys())
        lang_cur_setting = self.config.get("language", '')
        try:
            index = lang_keys.index(lang_cur_setting)
        except ValueError:  # not in list
            index = 0
        lang_combo.setCurrentIndex(index)
        if not self.config.is_modifiable('language'):
            for w in [lang_combo, lang_label]: w.setEnabled(False)

        def on_lang(x):
            lang_request = list(languages.keys())[lang_combo.currentIndex()]
            if lang_request != self.config.get('language'):
                self.config.set_key("language", lang_request, True)
                self.need_restart = True

        lang_combo.currentIndexChanged.connect(on_lang)
        gui_widgets.append((lang_label, lang_combo))

        nz_help = _(
            'Number of zeros displayed after the decimal point. For example, if this is set to 2, "1." will be displayed as "1.00"')
        nz_label = HelpLabel(_('Zeros after decimal point') + ':', nz_help)
        nz = QSpinBox()
        nz.setMinimum(0)
        nz.setMaximum(self.window.decimal_point)
        nz.setValue(self.window.num_zeros)
        if not self.config.is_modifiable('num_zeros'):
            for w in [nz, nz_label]: w.setEnabled(False)

        def on_nz():
            value = nz.value()
            if self.window.num_zeros != value:
                self.window.num_zeros = value
                self.config.set_key('num_zeros', value, True)
                self.window.history_list.update()
                self.window.address_list.update()

        nz.valueChanged.connect(on_nz)
        gui_widgets.append((nz_label, nz))

        def on_dynfee(x):
            self.config.set_key('dynamic_fees', x == Qt.Checked)
            self.window.fee_slider.update()

        dynfee_cb = QCheckBox(_('Use dynamic fees'))
        dynfee_cb.setChecked(self.config.is_dynfee())
        dynfee_cb.setToolTip(_("Use fees recommended by the server."))
        fee_widgets.append((dynfee_cb, None))
        dynfee_cb.stateChanged.connect(on_dynfee)

        feebox_cb = QCheckBox(_('Edit fees manually'))
        feebox_cb.setChecked(self.config.get('show_fee', False))
        feebox_cb.setToolTip(_("Show fee edit box in send tab."))

        def on_feebox(x):
            self.config.set_key('show_fee', x == Qt.Checked)
            self.window.fee_e.setVisible(bool(x))

        feebox_cb.stateChanged.connect(on_feebox)
        fee_widgets.append((feebox_cb, None))

        use_rbf = self.config.get('use_rbf', True)
        use_rbf_cb = QCheckBox(_('Use Replace-By-Fee'))
        use_rbf_cb.setChecked(use_rbf)
        use_rbf_cb.setToolTip(
            _('If you check this box, your transactions will be marked as non-final,') + '\n' + \
            _(
                'and you will have the possibility, while they are unconfirmed, to replace them with transactions that pay higher fees.') + '\n' + \
            _('Note that some merchants do not accept non-final transactions until they are confirmed.'))

        def on_use_rbf(x):
            self.config.set_key('use_rbf', x == Qt.Checked)

        use_rbf_cb.stateChanged.connect(on_use_rbf)
        fee_widgets.append((use_rbf_cb, None))

        batch_rbf_cb = QCheckBox(_('Batch RBF transactions'))
        batch_rbf_cb.setChecked(self.config.get('batch_rbf', False))
        batch_rbf_cb.setEnabled(use_rbf)
        batch_rbf_cb.setToolTip(
            _(
                'If you check this box, your unconfirmed transactions will be consolidated into a single transaction.') + '\n' + \
            _('This will save fees.'))

        def on_batch_rbf(x):
            self.config.set_key('batch_rbf', bool(x))

        batch_rbf_cb.stateChanged.connect(on_batch_rbf)
        fee_widgets.append((batch_rbf_cb, None))

        msg = _('OpenAlias record, used to receive coins and to sign payment requests.') + '\n\n' \
              + _('The following alias providers are available:') + '\n' \
              + '\n'.join(['https://cryptoname.co/', 'http://xmr.link']) + '\n\n' \
              + 'For more information, see http://openalias.org'
        alias_label = HelpLabel(_('OpenAlias') + ':', msg)
        alias = self.config.get('alias', '')
        self.alias_e = QLineEdit(alias)

        self.set_alias_color()
        self.window.alias_received_signal.connect(self.set_alias_color)
        self.alias_e.editingFinished.connect(self.on_alias_edit)
        id_widgets.append((alias_label, self.alias_e))

        # SSL certificate
        msg = ' '.join([
            _('SSL certificate used to sign payment requests.'),
            _('Use setconfig to set ssl_chain and ssl_privkey.'),
        ])
        if self.config.get('ssl_privkey') or self.config.get('ssl_chain'):
            try:
                SSL_identity = paymentrequest.check_ssl_config(self.config)
                SSL_error = None
            except BaseException as e:
                SSL_identity = "error"
                SSL_error = str(e)
        else:
            SSL_identity = ""
            SSL_error = None
        SSL_id_label = HelpLabel(_('SSL certificate') + ':', msg)
        SSL_id_e = QLineEdit(SSL_identity)
        SSL_id_e.setStyleSheet(RED_BG if SSL_error else GREEN_BG if SSL_identity else '')
        if SSL_error:
            SSL_id_e.setToolTip(SSL_error)
        SSL_id_e.setReadOnly(True)
        id_widgets.append((SSL_id_label, SSL_id_e))

        units = ['QTUM', 'mQTUM', 'bits']
        msg = _('Base unit of your wallet.') \
              + '\n1QTUM=1000mQTUM.\n' \
              + _(' These settings affects the fields in the Send tab') + ' '
        unit_label = HelpLabel(_('Base unit') + ':', msg)
        unit_combo = QComboBox()
        unit_combo.addItems(units)
        unit_combo.setCurrentIndex(units.index(self.window.base_unit()))

        def on_unit(x, nz):
            unit_result = units[unit_combo.currentIndex()]
            if self.window.base_unit() == unit_result:
                return
            edits = self.amount_e, self.fee_e, self.receive_amount_e
            amounts = [edit.get_amount() for edit in edits]
            if unit_result == 'QTUM':
                self.window.decimal_point = 8
            elif unit_result == 'mQTUM':
                self.window.decimal_point = 5
            elif unit_result == 'bits':
                self.window.decimal_point = 2
            else:
                raise Exception('Unknown base unit')
            self.config.set_key('decimal_point', self.window.decimal_point, True)
            nz.setMaximum(self.window.decimal_point)
            self.window.history_list.update()
            self.window.request_list.update()
            self.window.address_list.update()
            for edit, amount in zip(edits, amounts):
                edit.setAmount(amount)
            self.window.update_status()

        unit_combo.currentIndexChanged.connect(lambda x: on_unit(x, nz))
        gui_widgets.append((unit_label, unit_combo))

        block_explorers = sorted(util.block_explorer_info().keys())
        msg = _('Choose which online block explorer to use for functions that open a web browser')
        block_ex_label = HelpLabel(_('Online Block Explorer') + ':', msg)
        block_ex_combo = QComboBox()
        block_ex_combo.addItems(block_explorers)
        block_ex_combo.setCurrentIndex(block_ex_combo.findText(util.block_explorer(self.config)))

        def on_be(x):
            be_result = block_explorers[block_ex_combo.currentIndex()]
            self.config.set_key('block_explorer', be_result, True)

        block_ex_combo.currentIndexChanged.connect(on_be)
        gui_widgets.append((block_ex_label, block_ex_combo))

        from qtum_electrum import qrscanner
        system_cameras = qrscanner._find_system_cameras()
        qr_combo = QComboBox()
        qr_combo.addItem("Default", "default")
        for camera, device in system_cameras.items():
            qr_combo.addItem(camera, device)
        # combo.addItem("Manually specify a device", config.get("video_device"))
        index = qr_combo.findData(self.config.get("video_device"))
        qr_combo.setCurrentIndex(index)
        msg = _("Install the zbar package to enable this.")
        qr_label = HelpLabel(_('Video Device') + ':', msg)
        qr_combo.setEnabled(qrscanner.libzbar is not None)
        on_video_device = lambda x: self.config.set_key("video_device", qr_combo.itemData(x), True)
        qr_combo.currentIndexChanged.connect(on_video_device)
        gui_widgets.append((qr_label, qr_combo))

        filelogging_cb = QCheckBox(_("Write logs to file"))
        filelogging_cb.setChecked(bool(self.config.get('log_to_file', False)))
        def on_set_filelogging(v):
            self.config.set_key('log_to_file', v == Qt.Checked, save=True)
            self.need_restart = True
        filelogging_cb.stateChanged.connect(on_set_filelogging)
        filelogging_cb.setToolTip(_('Debug logs can be persisted to disk. These are useful for troubleshooting.'))
        gui_widgets.append((filelogging_cb, None))

        usechange_cb = QCheckBox(_('Use change addresses'))
        usechange_cb.setChecked(self.window.wallet.use_change)
        if not self.config.is_modifiable('use_change'): usechange_cb.setEnabled(False)

        def on_usechange(x):
            usechange_result = x == Qt.Checked
            if self.window.wallet.use_change != usechange_result:
                self.window.wallet.use_change = usechange_result
                self.window.wallet.storage.put('use_change', self.window.wallet.use_change)
                multiple_cb.setEnabled(self.window.wallet.use_change)

        usechange_cb.stateChanged.connect(on_usechange)
        usechange_cb.setToolTip(
            _('Using change addresses makes it more difficult for other people to track your transactions.'))
        tx_widgets.append((usechange_cb, None))

        def on_multiple(x):
            multiple = x == Qt.Checked
            if self.wallet.multiple_change != multiple:
                self.wallet.multiple_change = multiple
                self.wallet.storage.put('multiple_change', multiple)

        multiple_change = self.wallet.multiple_change
        multiple_cb = QCheckBox(_('Use multiple change addresses'))
        multiple_cb.setEnabled(self.wallet.use_change)
        multiple_cb.setToolTip('\n'.join([
            _('In some cases, use up to 3 change addresses in order to break '
              'up large coin amounts and obfuscate the recipient address.'),
            _('This may result in higher transactions fees.')
        ]))
        multiple_cb.setChecked(multiple_change)
        multiple_cb.stateChanged.connect(on_multiple)
        tx_widgets.append((multiple_cb, None))

        def fmt_docs(key, klass):
            lines = [ln.lstrip(" ") for ln in klass.__doc__.split("\n")]
            return '\n'.join([key, "", " ".join(lines)])

        choosers = sorted(coinchooser.COIN_CHOOSERS.keys())
        if len(choosers) > 1:
            chooser_name = coinchooser.get_name(self.config)
            msg = _('Choose coin (UTXO) selection method.  The following are available:\n\n')
            msg += '\n\n'.join(fmt_docs(*item) for item in coinchooser.COIN_CHOOSERS.items())
            chooser_label = HelpLabel(_('Coin selection') + ':', msg)
            chooser_combo = QComboBox()
            chooser_combo.addItems(choosers)
            i = choosers.index(chooser_name) if chooser_name in choosers else 0
            chooser_combo.setCurrentIndex(i)

            def on_chooser(x):
                chooser_name = choosers[chooser_combo.currentIndex()]
                self.config.set_key('coin_chooser', chooser_name)

            chooser_combo.currentIndexChanged.connect(on_chooser)
            tx_widgets.append((chooser_label, chooser_combo))

        def on_unconf(x):
            self.config.set_key('confirmed_only', bool(x))

        conf_only = self.config.get('confirmed_only', False)
        unconf_cb = QCheckBox(_('Spend only confirmed coins'))
        unconf_cb.setToolTip(_('Spend only confirmed inputs.'))
        unconf_cb.setChecked(conf_only)
        unconf_cb.stateChanged.connect(on_unconf)
        tx_widgets.append((unconf_cb, None))

        # Fiat Currency
        hist_checkbox = QCheckBox()
        fiat_address_checkbox = QCheckBox()
        ccy_combo = QComboBox()
        ex_combo = QComboBox()

        def update_currencies():
            if not self.window.fx: return
            currencies = sorted(self.fx.get_currencies(self.window.fx.get_history_config()))
            ccy_combo.clear()
            ccy_combo.addItems([_('None')] + currencies)
            if self.window.fx.is_enabled():
                ccy_combo.setCurrentIndex(ccy_combo.findText(self.window.fx.get_currency()))

        def update_history_cb():
            if not self.window.fx: return
            hist_checkbox.setChecked(self.window.fx.get_history_config())
            hist_checkbox.setEnabled(self.window.fx.is_enabled())

        def update_fiat_address_cb():
            if not self.window.fx: return
            fiat_address_checkbox.setChecked(self.window.fx.get_fiat_address_config())

        def update_exchanges():
            if not self.window.fx: return
            b = self.window.fx.is_enabled()
            ex_combo.setEnabled(b)
            if b:
                h = self.window.fx.get_history_config()
                c = self.window.fx.get_currency()
                exchanges = self.window.fx.get_exchanges_by_ccy(c, h)
            else:
                exchanges = self.window.fx.get_exchanges_by_ccy('USD', False)
            ex_combo.clear()
            ex_combo.addItems(sorted(exchanges))
            ex_combo.setCurrentIndex(ex_combo.findText(self.window.fx.config_exchange()))

        def on_currency(hh):
            if not self.window.fx: return
            b = bool(ccy_combo.currentIndex())
            ccy = str(ccy_combo.currentText()) if b else None
            self.window.fx.set_enabled(b)
            if b and ccy != self.window.fx.ccy:
                self.window.fx.set_currency(ccy)
            update_history_cb()
            update_exchanges()
            self.window.update_fiat()

        def on_exchange(idx):
            exchange = str(ex_combo.currentText())
            if self.window.fx and self.window.fx.is_enabled() and exchange and exchange != self.window.fx.exchange.name():
                self.window.fx.set_exchange(exchange)

        def on_history(checked):
            if not self.window.fx: return
            self.window.fx.set_history_config(checked)
            update_exchanges()
            self.window.history_list.refresh_headers()
            if self.window.fx.is_enabled() and checked:
                # reset timeout to get historical rates
                self.window.fx.timeout = 0

        def on_fiat_address(checked):
            if not self.window.fx: return
            self.window.fx.set_fiat_address_config(checked)
            self.window.address_list.refresh_headers()
            self.window.address_list.update()

        update_currencies()
        update_history_cb()
        update_fiat_address_cb()
        update_exchanges()
        ccy_combo.currentIndexChanged.connect(on_currency)
        hist_checkbox.stateChanged.connect(on_history)
        fiat_address_checkbox.stateChanged.connect(on_fiat_address)
        ex_combo.currentIndexChanged.connect(on_exchange)

        fiat_widgets = []
        fiat_widgets.append((QLabel(_('Fiat currency')), ccy_combo))
        fiat_widgets.append((QLabel(_('Show history rates')), hist_checkbox))
        fiat_widgets.append((QLabel(_('Show Fiat balance for addresses')), fiat_address_checkbox))
        fiat_widgets.append((QLabel(_('Source')), ex_combo))

        tabs_info = [
            (fee_widgets, _('Fees')),
            (tx_widgets, _('Transactions')),
            (gui_widgets, _('Appearance')),
            (fiat_widgets, _('Fiat')),
            (id_widgets, _('Identity')),
        ]
        for widgets, name in tabs_info:
            tab = QWidget()
            grid = QGridLayout(tab)
            grid.setColumnStretch(0, 1)
            for a, b in widgets:
                i = grid.rowCount()
                if b:
                    if a:
                        grid.addWidget(a, i, 0)
                    grid.addWidget(b, i, 1)
                else:
                    grid.addWidget(a, i, 0, 1, 2)
            tabs.addTab(tab, name)

        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)

    def set_alias_color(self):
        if not self.config.get('alias'):
            self.alias_e.setStyleSheet("")
            return
        if self.window.alias_info:
            alias_addr, alias_name, validated = self.window.alias_info
            self.alias_e.setStyleSheet(GREEN_BG if validated else RED_BG)
        else:
            self.alias_e.setStyleSheet(RED_BG)

    def on_alias_edit(self):
        self.alias_e.setStyleSheet("")
        alias = str(self.alias_e.text())
        self.config.set_key('alias', alias, True)
        if alias:
            self.window.fetch_alias()
