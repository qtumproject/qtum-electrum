# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Thomas Voegtlin
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

import os
import sys
import copy
import traceback
from functools import partial
from typing import List, TYPE_CHECKING, Tuple, NamedTuple, Any, Dict, Optional, Union

from . import bitcoin
from . import keystore
from . import mnemonic
from . import constants
from .bip32 import is_bip32_derivation, xpub_type, normalize_bip32_derivation, BIP32Node
from .keystore import bip44_derivation, purpose48_derivation, Hardware_KeyStore, KeyStore, bip39_to_seed
from .wallet import (Imported_Wallet, Standard_Wallet, Multisig_Wallet,
                     wallet_types, Wallet, Abstract_Wallet)
from .storage import WalletStorage, StorageEncryptionVersion
from .wallet_db import WalletDB
from .i18n import _
from .util import UserCancelled, InvalidPassword, WalletFileException, UserFacingException
from .simple_config import SimpleConfig
from .plugin import Plugins, HardwarePluginLibraryUnavailable
from .logging import Logger
from .plugins.hw_wallet.plugin import OutdatedHwFirmwareException, HW_PluginBase

if TYPE_CHECKING:
    from .plugin import DeviceInfo, BasePlugin


# hardware device setup purpose
HWD_SETUP_NEW_WALLET, HWD_SETUP_DECRYPT_WALLET = range(0, 2)


class ScriptTypeNotSupported(Exception): pass


class GoBack(Exception): pass


class ReRunDialog(Exception): pass


class ChooseHwDeviceAgain(Exception): pass


class WizardStackItem(NamedTuple):
    action: Any
    args: Any
    kwargs: Dict[str, Any]
    db_data: dict


class WizardWalletPasswordSetting(NamedTuple):
    password: Optional[str]
    encrypt_storage: bool
    storage_enc_version: StorageEncryptionVersion
    encrypt_keystore: bool


class BaseWizard(Logger):

    def __init__(self, config: SimpleConfig, plugins: Plugins):
        super(BaseWizard, self).__init__()
        Logger.__init__(self)
        self.config = config
        self.plugins = plugins
        self.data = {}
        self.pw_args = None  # type: Optional[WizardWalletPasswordSetting]
        self._stack = []  # type: List[WizardStackItem]
        self.plugin = None  # type: Optional[BasePlugin]
        self.keystores = []  # type: List[KeyStore]
        self.is_kivy = config.get('gui') == 'kivy'
        self.seed_type = None

    def set_icon(self, icon):
        pass

    def run(self, *args, **kwargs):
        action = args[0]
        args = args[1:]
        db_data = copy.deepcopy(self.data)
        self._stack.append(WizardStackItem(action, args, kwargs, db_data))
        if not action:
            return
        if type(action) is tuple:
            self.plugin, action = action
        if self.plugin and hasattr(self.plugin, action):
            f = getattr(self.plugin, action)
            f(self, *args, **kwargs)
        elif hasattr(self, action):
            f = getattr(self, action)
            f(*args, **kwargs)
        else:
            raise Exception("unknown action", action)

    def can_go_back(self):
        return len(self._stack) > 1

    def go_back(self, *, rerun_previous: bool = True) -> None:
        if not self.can_go_back():
            return
        # pop 'current' frame
        self._stack.pop()
        prev_frame = self._stack[-1]
        # try to undo side effects since we last entered 'previous' frame
        # FIXME only self.data is properly restored
        self.data = copy.deepcopy(prev_frame.db_data)

        if rerun_previous:
            # pop 'previous' frame
            self._stack.pop()
            # rerun 'previous' frame
            self.run(prev_frame.action, *prev_frame.args, **prev_frame.kwargs)

    def reset_stack(self):
        self._stack = []

    def new(self):
        title = _("Create new wallet")
        message = '\n'.join([
            _("What kind of wallet do you want to create?")
        ])
        wallet_kinds = [
            ('standard',  _("Standard wallet")),
            ('mobile', _("Qtum mobile wallet compatible")),
            ('qtcore', _("Qtum Qt Core wallet compatible")),
            # ('2fa', _("Wallet with two-factor authentication")),
            ('multisig',  _("Multi-signature wallet")),
            ('imported',  _("Import Qtum addresses or private keys")),
        ]
        choices = [pair for pair in wallet_kinds if pair[0] in wallet_types]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.on_wallet_type)

    def upgrade_db(self, storage, db):
        exc = None  # type: Optional[Exception]
        def on_finished():
            if exc is None:
                self.terminate(storage=storage, db=db)
            else:
                raise exc
        def do_upgrade():
            nonlocal exc
            try:
                db.upgrade()
            except Exception as e:
                exc = e
        self.waiting_dialog(do_upgrade, _('Upgrading wallet format...'), on_finished=on_finished)

    def run_task_without_blocking_gui(self, task, *, msg: str = None) -> Any:
        """Perform a task in a thread without blocking the GUI.
        Returns the result of 'task', or raises the same exception.
        This method blocks until 'task' is finished.
        """
        raise NotImplementedError()

    def load_2fa(self):
        self.data['wallet_type'] = '2fa'
        self.data['use_trustedcoin'] = True
        self.plugin = self.plugins.load_plugin('trustedcoin')

    def on_wallet_type(self, choice):
        self.data['wallet_type'] = self.wallet_type = choice

        if choice == 'qtcore':
            action = 'restore_from_key'
        elif choice in ('standard', 'mobile'):
            action = 'choose_keystore'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == '2fa':
            self.load_2fa()
            action = self.plugin.get_action(self.data)
        elif choice == 'imported':
            action = 'import_addresses_or_keys'
        self.run(action)

    def choose_multisig(self):
        def on_multisig(m, n):
            multisig_type = "%dof%d" % (m, n)
            self.data['wallet_type'] = multisig_type
            self.n = n
            self.run('choose_keystore')
        self.multisig_dialog(run_next=on_multisig)

    def choose_keystore(self):
        assert self.wallet_type in ['standard', 'multisig', 'mobile', 'qtcore']
        i = len(self.keystores)
        title = _('Add cosigner') + ' (%d of %d)'%(i+1, self.n) if self.wallet_type=='multisig' else _('Keystore')
        if self.wallet_type == 'mobile':
            message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
            choices = [
                ('restore_from_seed', _('I already have a seed')),
            ]
        elif self.wallet_type == 'qtcore':
            message = _('Do you want to create a new wallet, or to restore a wallet using an existing key?')
            choices = [
                ('restore_from_key', _('Use public or private keys')),
            ]
        elif self.wallet_type =='standard' or i==0:
            message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
            choices = [
                ('choose_seed_type', _('Create a new seed')),
                ('restore_from_seed', _('I already have a seed')),
                ('restore_from_key', _('Use a master key')),
            ]
            if not self.is_kivy:
                choices.append(('choose_hw_device',  _('Use a hardware device')))
        else:
            message = _('Add a cosigner to your multi-sig wallet')
            choices = [
                ('restore_from_key', _('Enter cosigner key')),
                ('restore_from_seed', _('Enter cosigner seed')),
            ]
            if not self.is_kivy:
                choices.append(('choose_hw_device',  _('Cosign with hardware device')))

        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def import_addresses_or_keys(self):
        v = lambda x: keystore.is_address_list(x) or keystore.is_private_key_list(x, raise_on_error=True)
        title = _("Import Qtum Addresses")
        message = _("Enter a list of Qtum addresses (this will create a watching-only wallet), or a list of private keys.")
        self.add_xpub_dialog(title=title, message=message, run_next=self.on_import,
                             is_valid=v, allow_multi=True, show_wif_help=True)

    def on_import(self, text):
        # text is already sanitized by is_address_list and is_private_keys_list
        if keystore.is_address_list(text):
            self.data['addresses'] = {}
            for addr in text.split():
                assert bitcoin.is_address(addr)
                self.data['addresses'][addr] = {}
        elif keystore.is_private_key_list(text):
            self.data['addresses'] = {}
            k = keystore.Imported_KeyStore({})
            keys = keystore.get_private_keys(text)
            for pk in keys:
                assert bitcoin.is_private_key(pk)
                txin_type, pubkey = k.import_privkey(pk, None)
                addr = bitcoin.pubkey_to_address(txin_type, pubkey)
                self.data['addresses'][addr] = {'type':txin_type, 'pubkey':pubkey}
            self.keystores.append(k)
        else:
            return self.terminate()
        return self.run('create_wallet')

    def restore_from_key(self):
        if self.wallet_type == 'standard':
            v = keystore.is_master_key
            title = _("Create keystore from a master key")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub/ypub/zpub)."),
                _("To create a spending wallet, please enter a master private key (xprv/yprv/zprv).")
            ])
            self.add_xpub_dialog(title=title, message=message, run_next=self.on_restore_from_key, is_valid=v)
        else:
            i = len(self.keystores) + 1
            self.add_cosigner_dialog(index=i, run_next=self.on_restore_from_key, is_valid=keystore.is_bip32_key)

    def on_restore_from_key(self, text):
        k = keystore.from_master_key(text)
        self.on_keystore(k)

    def choose_hw_device(self, purpose=HWD_SETUP_NEW_WALLET, *, storage: WalletStorage = None):
        while True:
            try:
                self._choose_hw_device(purpose=purpose, storage=storage)
            except ChooseHwDeviceAgain:
                pass
            else:
                break

    def _choose_hw_device(self, *, purpose, storage: WalletStorage = None):
        title = _('Hardware Keystore')
        # check available plugins
        supported_plugins = self.plugins.get_hardware_support()
        devices = []  # type: List[Tuple[str, DeviceInfo]]
        devmgr = self.plugins.device_manager
        debug_msg = ''

        def failed_getting_device_infos(name, e):
            nonlocal debug_msg
            err_str_oneline = ' // '.join(str(e).splitlines())
            self.logger.warning(f'error getting device infos for {name}: {err_str_oneline}')
            indented_error_msg = '    '.join([''] + str(e).splitlines(keepends=True))
            debug_msg += f'  {name}: (error getting device infos)\n{indented_error_msg}\n'

        # scan devices
        try:
            scanned_devices = self.run_task_without_blocking_gui(task=devmgr.scan_devices,
                                                                 msg=_("Scanning devices..."))
        except BaseException as e:
            self.logger.info('error scanning devices: {}'.format(repr(e)))
            debug_msg = '  {}:\n    {}'.format(_('Error scanning devices'), e)
        else:
            for splugin in supported_plugins:
                name, plugin = splugin.name, splugin.plugin
                # plugin init errored?
                if not plugin:
                    e = splugin.exception
                    indented_error_msg = '    '.join([''] + str(e).splitlines(keepends=True))
                    debug_msg += f'  {name}: (error during plugin init)\n'
                    debug_msg += '    {}\n'.format(_('You might have an incompatible library.'))
                    debug_msg += f'{indented_error_msg}\n'
                    continue
                # see if plugin recognizes 'scanned_devices'
                try:
                    # FIXME: side-effect: unpaired_device_info sets client.handler
                    device_infos = devmgr.list_pairable_device_infos(handler=None, plugin=plugin,
                                                                     devices=scanned_devices, include_failing_clients=True)
                except HardwarePluginLibraryUnavailable as e:
                    failed_getting_device_infos(name, e)
                    continue
                except BaseException as e:
                    self.logger.exception('')
                    failed_getting_device_infos(name, e)
                    continue
                device_infos_failing = list(filter(lambda di: di.exception is not None, device_infos))
                for di in device_infos_failing:
                    failed_getting_device_infos(name, di.exception)
                device_infos_working = list(filter(lambda di: di.exception is None, device_infos))
                devices += list(map(lambda x: (name, x), device_infos_working))
        if not debug_msg:
            debug_msg = '  {}'.format(_('No exceptions encountered.'))
        if not devices:
            msg = (_('No hardware device detected.') + '\n' +
                   _('To trigger a rescan, press \'Next\'.') + '\n\n')
            if sys.platform == 'win32':
                msg += _('If your device is not detected on Windows, go to "Settings", "Devices", "Connected devices", '
                         'and do "Remove device". Then, plug your device again.') + '\n'
                msg += _('While this is less than ideal, it might help if you run Electrum as Administrator.') + '\n'
            else:
                msg += _('On Linux, you might have to add a new permission to your udev rules.') + '\n'
            msg += '\n\n'
            msg += _('Debug message') + '\n' + debug_msg
            self.confirm_dialog(title=title, message=msg,
                                run_next=lambda x: None)
            raise ChooseHwDeviceAgain()
        # select device
        self.devices = devices
        choices = []
        for name, info in devices:
            state = _("initialized") if info.initialized else _("wiped")
            label = info.label or _("An unnamed {}").format(name)
            try: transport_str = info.device.transport_ui_string[:20]
            except: transport_str = 'unknown transport'
            descr = f"{label} [{info.model_name or name}, {state}, {transport_str}]"
            choices.append(((name, info), descr))
        msg = _('Select a device') + ':'
        self.choice_dialog(title=title, message=msg, choices=choices,
                           run_next=lambda *args: self.on_device(*args, purpose=purpose, storage=storage))

    def on_device(self, name, device_info: 'DeviceInfo', *, purpose, storage: WalletStorage = None):
        self.plugin = self.plugins.get_plugin(name)
        assert isinstance(self.plugin, HW_PluginBase)
        devmgr = self.plugins.device_manager
        try:
            client = self.plugin.setup_device(device_info, self, purpose)
        except OSError as e:
            self.show_error(_('We encountered an error while connecting to your device:')
                            + '\n' + str(e) + '\n'
                            + _('To try to fix this, we will now re-pair with your device.') + '\n'
                            + _('Please try again.'))
            devmgr.unpair_id(device_info.device.id_)
            raise ChooseHwDeviceAgain()
        except OutdatedHwFirmwareException as e:
            if self.question(e.text_ignore_old_fw_and_continue(), title=_("Outdated device firmware")):
                self.plugin.set_ignore_outdated_fw()
                # will need to re-pair
                devmgr.unpair_id(device_info.device.id_)
            raise ChooseHwDeviceAgain()
        except GoBack:
            raise ChooseHwDeviceAgain()
        except (UserCancelled, ReRunDialog):
            raise
        except UserFacingException as e:
            self.show_error(str(e))
            raise ChooseHwDeviceAgain()
        except BaseException as e:
            self.logger.exception('')
            self.show_error(str(e))
            raise ChooseHwDeviceAgain()

        if purpose == HWD_SETUP_NEW_WALLET:
            def f(derivation, script_type):
                derivation = normalize_bip32_derivation(derivation)
                self.run('on_hw_derivation', name, device_info, derivation, script_type)
            self.derivation_and_script_type_dialog(f)
        elif purpose == HWD_SETUP_DECRYPT_WALLET:
            password = client.get_password_for_storage_encryption()
            try:
                storage.decrypt(password)
            except InvalidPassword:
                # try to clear session so that user can type another passphrase
                if hasattr(client, 'clear_session'):  # FIXME not all hw wallet plugins have this
                    client.clear_session()
                raise
        else:
            raise Exception('unknown purpose: %s' % purpose)

    def derivation_and_script_type_dialog(self, f, *, get_account_xpub=None):
        message1 = _('Choose the type of addresses in your wallet.')
        message2 = ' '.join([
            _('You can override the suggested derivation path.'),
            _('If you are not sure what this is, leave this field unchanged.')
        ])
        hide_choices = False
        if self.wallet_type == 'multisig':
            # There is no general standard for HD multisig.
            # For legacy, this is partially compatible with BIP45; assumes index=0
            # For segwit, a custom path is used, as there is no standard at all.
            default_choice_idx = 2
            choices = [
                ('standard',   'legacy multisig (p2sh)',            normalize_bip32_derivation(f"m/45'/{constants.net.BIP44_COIN_TYPE}'/0")),
                ('p2wsh-p2sh', 'p2sh-segwit multisig (p2wsh-p2sh)', purpose48_derivation(0, xtype='p2wsh-p2sh')),
                ('p2wsh',      'native segwit multisig (p2wsh)',    purpose48_derivation(0, xtype='p2wsh')),
            ]
            # if this is not the first cosigner, pre-select the expected script type,
            # and hide the choices
            script_type = self.get_script_type_of_wallet()
            if script_type is not None:
                script_types = [*zip(*choices)][0]
                chosen_idx = script_types.index(script_type)
                default_choice_idx = chosen_idx
                hide_choices = True
        else:
            default_choice_idx = 0
            choices = [
                ('standard',    'legacy (p2pkh)',            bip44_derivation(0, bip43_purpose=44)),
                ('p2wpkh-p2sh', 'p2sh-segwit (p2wpkh-p2sh)', bip44_derivation(0, bip43_purpose=49)),
                ('p2wpkh',      'native segwit (p2wpkh)',    bip44_derivation(0, bip43_purpose=84)),
            ]

            if self.plugin is not None and self.plugin.name in ["trezor", "safe_t"]:
                choices = [
                    ('standard', 'legacy (p2pkh) (recommend)',
                     bip44_derivation(0, bip43_purpose=44, coin=constants.net.SLIP_COIN_TYPE)),
                    ('p2wpkh-p2sh', 'p2sh-segwit (p2wpkh-p2sh) (recommend)',
                     bip44_derivation(0, bip43_purpose=49, coin=constants.net.SLIP_COIN_TYPE)),
                    ('p2wpkh', 'native segwit (p2wpkh) (recommend)',
                     bip44_derivation(0, bip43_purpose=84, coin=constants.net.SLIP_COIN_TYPE)),
                    ('standard',    'legacy (p2pkh) (old)',            bip44_derivation(0, bip43_purpose=44)),
                    ('p2wpkh-p2sh', 'p2sh-segwit (p2wpkh-p2sh) (old)', bip44_derivation(0, bip43_purpose=49)),
                    ('p2wpkh',      'native segwit (p2wpkh) (old)',    bip44_derivation(0, bip43_purpose=84)),
                ]

        while True:
            try:
                self.derivation_and_script_type_gui_specific_dialog(
                    run_next=f,
                    title=_('Script type and Derivation path'),
                    message1=message1,
                    message2=message2,
                    choices=choices,
                    test_text=is_bip32_derivation,
                    default_choice_idx=default_choice_idx,
                    get_account_xpub=get_account_xpub,
                    hide_choices=hide_choices,
                )
                return
            except ScriptTypeNotSupported as e:
                self.show_error(e)
                # let the user choose again

    def on_hw_derivation(self, name, device_info: 'DeviceInfo', derivation, xtype):
        from .keystore import hardware_keystore
        devmgr = self.plugins.device_manager
        assert isinstance(self.plugin, HW_PluginBase)
        try:
            xpub = self.plugin.get_xpub(device_info.device.id_, derivation, xtype, self)
            client = devmgr.client_by_id(device_info.device.id_, scan_now=False)
            if not client: raise Exception("failed to find client for device id")
            root_fingerprint = client.request_root_fingerprint_from_device()
            label = client.label()  # use this as device_info.label might be outdated!
            soft_device_id = client.get_soft_device_id()  # use this as device_info.device_id might be outdated!
        except ScriptTypeNotSupported:
            raise  # this is handled in derivation_dialog
        except BaseException as e:
            self.logger.exception('')
            self.show_error(e)
            raise ChooseHwDeviceAgain()
        d = {
            'type': 'hardware',
            'hw_type': name,
            'derivation': derivation,
            'root_fingerprint': root_fingerprint,
            'xpub': xpub,
            'label': label,
            'soft_device_id': soft_device_id,
        }
        try:
            client.manipulate_keystore_dict_during_wizard_setup(d)
        except Exception as e:
            self.logger.exception('')
            self.show_error(e)
            raise ChooseHwDeviceAgain()
        k = hardware_keystore(d)
        self.on_keystore(k)

    def passphrase_dialog(self, run_next, is_restoring=False):
        title = _('Seed extension')
        message = '\n'.join([
            _('You may extend your seed with custom words.'),
            _('Your seed extension must be saved together with your seed.'),
        ])
        warning = '\n'.join([
            _('Note that this is NOT your encryption password.'),
            _('If you do not know what this is, leave this field empty.'),
        ])
        warn_issue4566 = is_restoring and self.seed_type == 'bip39'
        self.line_dialog(title=title, message=message, warning=warning,
                         default='', test=lambda x:True, run_next=run_next,
                         warn_issue4566=warn_issue4566)

    def restore_from_seed(self):
        self.opt_bip39 = True
        self.opt_ext = True
        is_cosigning_seed = lambda x: mnemonic.seed_type(x) in ['standard', 'segwit']
        if self.wallet_type == 'mobile':
            test = lambda x: len(list(x.split())) == 12
        elif self.wallet_type == 'standard':
            test = mnemonic.is_seed
        else:
            test = is_cosigning_seed
        self.restore_seed_dialog(run_next=self.on_restore_seed, test=test)

    def on_restore_seed(self, seed, is_bip39, is_ext):
        if self.wallet_type == 'mobile':
            self.seed_type = 'standard'
        else:
            self.seed_type = 'bip39' if is_bip39 else mnemonic.seed_type(seed)

        if self.seed_type == 'bip39':
            def f(passphrase):
                self.on_restore_bip39(seed, passphrase)
            self.passphrase_dialog(run_next=f, is_restoring=True) if is_ext else f('')
        elif self.seed_type in ['standard', 'segwit']:
            f = lambda passphrase: self.run('create_keystore', seed, passphrase)
            self.passphrase_dialog(run_next=f, is_restoring=True) if is_ext else f('')
        elif self.seed_type == 'old':
            self.run('create_keystore', seed, '')
        elif mnemonic.is_any_2fa_seed_type(self.seed_type):
            self.load_2fa()
            self.run('on_restore_seed', seed, is_ext)
        else:
            raise Exception('Unknown seed type', self.seed_type)

    def on_restore_bip39(self, seed, passphrase):
        def f(derivation, script_type):
            derivation = normalize_bip32_derivation(derivation)
            self.run('on_bip43', seed, passphrase, derivation, script_type)
        if self.wallet_type == 'standard':
            def get_account_xpub(account_path):
                root_seed = bip39_to_seed(seed, passphrase)
                root_node = BIP32Node.from_rootseed(root_seed, xtype="standard")
                account_node = root_node.subkey_at_private_derivation(account_path)
                account_xpub = account_node.to_xpub()
                return account_xpub
        else:
            get_account_xpub = None
        self.derivation_and_script_type_dialog(f, get_account_xpub=get_account_xpub)

    def create_keystore(self, seed, passphrase):
        if self.wallet_type == 'mobile':
            k = keystore.from_mobile_seed(seed)
        else:
            k = keystore.from_seed(seed, passphrase, self.wallet_type == 'multisig')
        self.on_keystore(k)

    def on_bip43(self, seed, passphrase, derivation, script_type):
        k = keystore.from_bip39_seed(seed, passphrase, derivation, xtype=script_type)
        self.on_keystore(k)

    def get_script_type_of_wallet(self) -> Optional[str]:
        if len(self.keystores) > 0:
            ks = self.keystores[0]
            if isinstance(ks, keystore.Xpub):
                return xpub_type(ks.xpub)
        return None

    def on_keystore(self, k: KeyStore):
        if self.wallet_type in ('mobile', 'qtcore'):
            self.keystores.append(k)
            self.run('create_wallet')
        has_xpub = isinstance(k, keystore.Xpub)
        if has_xpub:
            t1 = xpub_type(k.xpub)
        if self.wallet_type == 'standard':
            if has_xpub and t1 not in ['standard', 'p2wpkh', 'p2wpkh-p2sh']:
                self.show_error(_('Wrong key type') + ' %s'%t1)
                self.run('choose_keystore')
                return
            self.keystores.append(k)
            self.run('create_wallet')
        elif self.wallet_type == 'multisig':
            assert has_xpub
            if t1 not in ['standard', 'p2wsh', 'p2wsh-p2sh']:
                self.show_error(_('Wrong key type') + ' %s'%t1)
                self.run('choose_keystore')
                return
            if k.xpub in map(lambda x: x.xpub, self.keystores):
                self.show_error(_('Error: duplicate master public key'))
                self.run('choose_keystore')
                return
            if len(self.keystores)>0:
                t2 = xpub_type(self.keystores[0].xpub)
                if t1 != t2:
                    self.show_error(_('Cannot add this cosigner:') + '\n' + "Their key type is '%s', we are '%s'"%(t1, t2))
                    self.run('choose_keystore')
                    return
            if len(self.keystores) == 0:
                xpub = k.get_master_public_key()
                self.reset_stack()
                self.keystores.append(k)
                self.run('show_xpub_and_add_cosigners', xpub)
                return
            self.reset_stack()
            self.keystores.append(k)
            if len(self.keystores) < self.n:
                self.run('choose_keystore')
            else:
                self.run('create_wallet')

    def create_wallet(self):
        encrypt_keystore = any(k.may_have_password() for k in self.keystores)
        # note: the following condition ("if") is duplicated logic from
        # wallet.get_available_storage_encryption_version()

        if self.wallet_type in ['mobile', 'qtcore']:
            self.on_password(None, encrypt_storage=False, encrypt_keystore=False)

        elif self.wallet_type == 'standard' and isinstance(self.keystores[0], Hardware_KeyStore):
            # offer encrypting with a pw derived from the hw device
            k = self.keystores[0]  # type: Hardware_KeyStore
            assert isinstance(self.plugin, HW_PluginBase)
            try:
                k.handler = self.plugin.create_handler(self)
                password = k.get_password_for_storage_encryption()
            except UserCancelled:
                devmgr = self.plugins.device_manager
                devmgr.unpair_xpub(k.xpub)
                raise ChooseHwDeviceAgain()
            except BaseException as e:
                self.logger.exception('')
                self.show_error(str(e))
                raise ChooseHwDeviceAgain()
            self.request_storage_encryption(
                run_next=lambda encrypt_storage: self.on_password(
                    password,
                    encrypt_storage=encrypt_storage,
                    storage_enc_version=StorageEncryptionVersion.XPUB_PASSWORD,
                    encrypt_keystore=False))
        else:
            # reset stack to disable 'back' button in password dialog
            self.reset_stack()
            # prompt the user to set an arbitrary password
            self.request_password(
                run_next=lambda password, encrypt_storage: self.on_password(
                    password,
                    encrypt_storage=encrypt_storage,
                    storage_enc_version=StorageEncryptionVersion.USER_PASSWORD,
                    encrypt_keystore=encrypt_keystore),
                force_disable_encrypt_cb=not encrypt_keystore)

    def on_password(self, password, *, encrypt_storage: bool,
                    storage_enc_version=StorageEncryptionVersion.USER_PASSWORD,
                    encrypt_keystore: bool):
        for k in self.keystores:
            if k.may_have_password():
                k.update_password(None, password)

        if self.wallet_type == 'qtcore':
            self.data['seed_type'] = self.seed_type
            keys = self.keystores[0].dump()
            self.data['keystore'] = keys
        elif self.wallet_type == 'mobile':
            self.data['seed_type'] = self.seed_type
            keys = self.keystores[0].dump()
            self.data['keystore'] = keys
        elif self.wallet_type == 'standard':
            self.data['seed_type'] = self.seed_type
            keys = self.keystores[0].dump()
            self.data['keystore'] = keys
        elif self.wallet_type == 'multisig':
            for i, k in enumerate(self.keystores):
                self.data['x%d/'%(i+1)] = k.dump()
        elif self.wallet_type == 'imported':
            if len(self.keystores) > 0:
                keys = self.keystores[0].dump()
                self.data['keystore'] = keys
        else:
            raise Exception('Unknown wallet type')
        self.pw_args = WizardWalletPasswordSetting(password=password,
                                                   encrypt_storage=encrypt_storage,
                                                   storage_enc_version=storage_enc_version,
                                                   encrypt_keystore=encrypt_keystore)
        self.terminate()

    def create_storage(self, path) -> Tuple[WalletStorage, WalletDB]:
        if os.path.exists(path):
            raise Exception('file already exists at path')
        assert self.pw_args, f"pw_args not set?!"
        pw_args = self.pw_args
        self.pw_args = None  # clean-up so that it can get GC-ed
        storage = WalletStorage(path)
        if pw_args.encrypt_storage:
            storage.set_password(pw_args.password, enc_version=pw_args.storage_enc_version)
        db = WalletDB('', manual_upgrades=False)
        db.set_keystore_encryption(bool(pw_args.password) and pw_args.encrypt_keystore)
        for key, value in self.data.items():
            db.put(key, value)
        db.load_plugins()
        db.write(storage)
        return storage, db

    def terminate(self, *, storage: WalletStorage = None,
                  db: WalletDB = None,
                  aborted: bool = False) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def show_xpub_and_add_cosigners(self, xpub):
        self.show_xpub_dialog(xpub=xpub, run_next=lambda x: self.run('choose_keystore'))

    def choose_seed_type(self, message=None, choices=None):
        title = _('Choose Seed type')
        if message is None:
            message = ' '.join([
                _("The type of addresses used by your wallet will depend on your seed."),
                _("Segwit wallets use bech32 addresses, defined in BIP173."),
                _("Please note that websites and other wallets may not support these addresses yet."),
                _("Thus, you might want to keep using a non-segwit wallet in order to be able to receive bitcoins during the transition period.")
            ])
        if choices is None:
            choices = [
                ('create_standard_seed', _('Legacy')),
                ('create_segwit_seed', _('Segwit')),
            ]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def create_segwit_seed(self): self.create_seed('segwit')
    def create_standard_seed(self): self.create_seed('standard')

    def create_seed(self, seed_type):
        from . import mnemonic
        self.seed_type = seed_type
        seed = mnemonic.Mnemonic('en').make_seed(self.seed_type)
        self.opt_bip39 = False
        f = lambda x: self.request_passphrase(seed, x)
        self.show_seed_dialog(run_next=f, seed_text=seed)

    def request_passphrase(self, seed, opt_passphrase):
        if opt_passphrase:
            f = lambda x: self.confirm_seed(seed, x)
            self.passphrase_dialog(run_next=f)
        else:
            self.run('confirm_seed', seed, '')

    def confirm_seed(self, seed, passphrase):
        f = lambda x: self.confirm_passphrase(seed, passphrase)
        self.confirm_seed_dialog(run_next=f, test=lambda x: x==seed)

    def confirm_passphrase(self, seed, passphrase):
        f = lambda x: self.run('create_keystore', seed, x)
        if passphrase:
            title = _('Confirm Seed Extension')
            message = '\n'.join([
                _('Your seed extension must be saved together with your seed.'),
                _('Please type it here.'),
            ])
            self.line_dialog(run_next=f, title=title, message=message, default='', test=lambda x: x==passphrase)
        else:
            f('')

    def show_error(self, msg: Union[str, BaseException]) -> None:
        raise NotImplementedError()
