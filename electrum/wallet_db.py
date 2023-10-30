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
import os
import ast
import json
import copy
import threading
from collections import defaultdict
from functools import reduce
from typing import Dict, Optional, List, Tuple, Set, Iterable, NamedTuple, Sequence, TYPE_CHECKING, Union
import binascii

from . import util, bitcoin
from .util import profiler, WalletFileException, multisig_type, TxMinedInfo, bfh
from .invoices import PR_TYPE_ONCHAIN, Invoice
from .keystore import bip44_derivation
from .transaction import Transaction, TxOutpoint, tx_from_any, PartialTransaction, PartialTxOutput
from .logging import Logger
from .lnutil import LOCAL, REMOTE, FeeUpdate, UpdateAddHtlc, LocalConfig, RemoteConfig, Keypair, OnlyPubkeyKeypair, RevocationStore, ChannelBackupStorage
from .lnutil import ChannelConstraints, Outpoint, ShachainElement
from .json_db import StoredDict, JsonDB, locked, modifier
from .plugin import run_hook, plugin_loaders
from .paymentrequest import PaymentRequest
from .submarine_swaps import SwapData
from .bitcoin import Token, Delegation

if TYPE_CHECKING:
    from .storage import WalletStorage


# seed_version is now used for the version of the wallet file

OLD_SEED_VERSION = 4        # electrum versions < 2.0
NEW_SEED_VERSION = 11       # electrum versions >= 2.0
FINAL_SEED_VERSION = 32     # electrum >= 2.7 will set this to prevent
                            # old versions from overwriting new format


class TxFeesValue(NamedTuple):
    fee: Optional[int] = None
    is_calculated_by_us: bool = False
    num_inputs: Optional[int] = None


class WalletDB(JsonDB):

    def __init__(self, raw, *, manual_upgrades: bool):
        JsonDB.__init__(self, {})
        self._manual_upgrades = manual_upgrades
        self._called_after_upgrade_tasks = False
        if raw:  # loading existing db
            self.load_data(raw)
            self.load_plugins()
        else:  # creating new db
            self.put('seed_version', FINAL_SEED_VERSION)
            self._after_upgrade_tasks()

    def load_data(self, s):
        try:
            self.data = json.loads(s)
        except:
            try:
                d = ast.literal_eval(s)
                labels = d.get('labels', {})
            except Exception as e:
                raise WalletFileException("Cannot read wallet file. (parsing failed)")
            self.data = {}
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    self.logger.info(f'Failed to convert label to json format: {key}')
                    continue
                self.data[key] = value
        if not isinstance(self.data, dict):
            raise WalletFileException("Malformed wallet file (not dict)")

        if not self._manual_upgrades and self.requires_split():
            raise WalletFileException("This wallet has multiple accounts and must be split")

        if not self.requires_upgrade():
            self._after_upgrade_tasks()
        elif not self._manual_upgrades:
            self.upgrade()

    def requires_split(self):
        d = self.get('accounts', {})
        return len(d) > 1

    def get_split_accounts(self):
        result = []
        # backward compatibility with old wallets
        d = self.get('accounts', {})
        if len(d) < 2:
            return
        wallet_type = self.get('wallet_type')
        if wallet_type == 'old':
            assert len(d) == 2
            data1 = copy.deepcopy(self.data)
            data1['accounts'] = {'0': d['0']}
            data1['suffix'] = 'deterministic'
            data2 = copy.deepcopy(self.data)
            data2['accounts'] = {'/x': d['/x']}
            data2['seed'] = None
            data2['seed_version'] = None
            data2['master_public_key'] = None
            data2['wallet_type'] = 'imported'
            data2['suffix'] = 'imported'
            result = [data1, data2]

        elif wallet_type in ['bip44', 'trezor', 'keepkey', 'ledger', 'btchip', 'digitalbitbox', 'safe_t']:
            mpk = self.get('master_public_keys')
            for k in d.keys():
                i = int(k)
                x = d[k]
                if x.get("pending"):
                    continue
                xpub = mpk["x/%d'"%i]
                new_data = copy.deepcopy(self.data)
                # save account, derivation and xpub at index 0
                new_data['accounts'] = {'0': x}
                new_data['master_public_keys'] = {"x/0'": xpub}
                new_data['derivation'] = bip44_derivation(k)
                new_data['suffix'] = k
                result.append(new_data)
        else:
            raise WalletFileException("This wallet has multiple accounts and must be split")
        return result

    def requires_upgrade(self):
        return self.get_seed_version() < FINAL_SEED_VERSION

    @profiler
    def upgrade(self):
        self.logger.info('upgrading wallet format')
        if self._called_after_upgrade_tasks:
            # we need strict ordering between upgrade() and after_upgrade_tasks()
            raise Exception("'after_upgrade_tasks' must NOT be called before 'upgrade'")
        self._convert_imported()
        self._convert_wallet_type()
        self._convert_account()
        self._convert_version_13_b()
        self._convert_version_14()
        self._convert_version_15()
        self._convert_version_16()
        self._convert_version_17()
        self._convert_version_18()
        self._convert_version_19()
        self._convert_version_20()
        self._convert_version_21()
        self._convert_version_22()
        self._convert_version_23()
        self._convert_version_24()
        self._convert_version_25()
        self._convert_version_26()
        self._convert_version_27()
        self._convert_version_28()
        self._convert_version_29()
        self._convert_version_30()
        self._convert_version_31()
        self._convert_version_32()
        self.put('seed_version', FINAL_SEED_VERSION)  # just to be sure

        self._after_upgrade_tasks()

    def _after_upgrade_tasks(self):
        self._called_after_upgrade_tasks = True
        self._load_transactions()

    def _convert_wallet_type(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        wallet_type = self.get('wallet_type')
        if wallet_type == 'btchip': wallet_type = 'ledger'
        if self.get('keystore') or self.get('x1/') or wallet_type=='imported':
            return False
        assert not self.requires_split()
        seed_version = self.get_seed_version()
        seed = self.get('seed')
        xpubs = self.get('master_public_keys')
        xprvs = self.get('master_private_keys', {})
        mpk = self.get('master_public_key')
        keypairs = self.get('keypairs')
        key_type = self.get('key_type')
        if seed_version == OLD_SEED_VERSION or wallet_type == 'old':
            d = {
                'type': 'old',
                'seed': seed,
                'mpk': mpk,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif key_type == 'imported':
            d = {
                'type': 'imported',
                'keypairs': keypairs,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['xpub', 'standard']:
            xpub = xpubs["x/"]
            xprv = xprvs.get("x/")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
                'seed': seed,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['bip44']:
            xpub = xpubs["x/0'"]
            xprv = xprvs.get("x/0'")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['trezor', 'keepkey', 'ledger', 'digitalbitbox', 'safe_t']:
            xpub = xpubs["x/0'"]
            derivation = self.get('derivation', bip44_derivation(0))
            d = {
                'type': 'hardware',
                'hw_type': wallet_type,
                'xpub': xpub,
                'derivation': derivation,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif (wallet_type == '2fa') or multisig_type(wallet_type):
            for key in xpubs.keys():
                d = {
                    'type': 'bip32',
                    'xpub': xpubs[key],
                    'xprv': xprvs.get(key),
                }
                if key == 'x1/' and seed:
                    d['seed'] = seed
                self.put(key, d)
        else:
            raise WalletFileException('Unable to tell wallet type. Is this even a wallet file?')
        # remove junk
        self.put('master_public_key', None)
        self.put('master_public_keys', None)
        self.put('master_private_keys', None)
        self.put('derivation', None)
        self.put('seed', None)
        self.put('keypairs', None)
        self.put('key_type', None)

    def _convert_version_13_b(self):
        # version 13 is ambiguous, and has an earlier and a later structure
        if not self._is_upgrade_method_needed(0, 13):
            return

        if self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type') == 'imported':
                pubkeys = self.get('keystore').get('keypairs').keys()
                d = {'change': []}
                receiving_addresses = []
                for pubkey in pubkeys:
                    addr = bitcoin.pubkey_to_address('p2pkh', pubkey)
                    receiving_addresses.append(addr)
                d['receiving'] = receiving_addresses
                self.put('addresses', d)
                self.put('pubkeys', None)

        self.put('seed_version', 13)

    def _convert_version_14(self):
        # convert imported wallets for 3.0
        if not self._is_upgrade_method_needed(13, 13):
            return

        if self.get('wallet_type') =='imported':
            addresses = self.get('addresses')
            if type(addresses) is list:
                addresses = dict([(x, None) for x in addresses])
                self.put('addresses', addresses)
        elif self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type')=='imported':
                addresses = set(self.get('addresses').get('receiving'))
                pubkeys = self.get('keystore').get('keypairs').keys()
                assert len(addresses) == len(pubkeys)
                d = {}
                for pubkey in pubkeys:
                    addr = bitcoin.pubkey_to_address('p2pkh', pubkey)
                    assert addr in addresses
                    d[addr] = {
                        'pubkey': pubkey,
                        'redeem_script': None,
                        'type': 'p2pkh'
                    }
                self.put('addresses', d)
                self.put('pubkeys', None)
                self.put('wallet_type', 'imported')
        self.put('seed_version', 14)

    def _convert_version_15(self):
        if not self._is_upgrade_method_needed(14, 14):
            return
        if self.get('seed_type') == 'segwit':
            # should not get here; get_seed_version should have caught this
            raise Exception('unsupported derivation (development segwit, v14)')
        self.put('seed_version', 15)

    def _convert_version_16(self):
        # fixes issue #3193 for Imported_Wallets with addresses
        # also, previous versions allowed importing any garbage as an address
        #       which we now try to remove, see pr #3191
        if not self._is_upgrade_method_needed(15, 15):
            return

        def remove_address(addr):
            def remove_from_dict(dict_name):
                d = self.get(dict_name, None)
                if d is not None:
                    d.pop(addr, None)
                    self.put(dict_name, d)

            def remove_from_list(list_name):
                lst = self.get(list_name, None)
                if lst is not None:
                    s = set(lst)
                    s -= {addr}
                    self.put(list_name, list(s))

            # note: we don't remove 'addr' from self.get('addresses')
            remove_from_dict('addr_history')
            remove_from_dict('labels')
            remove_from_dict('payment_requests')
            remove_from_list('frozen_addresses')

        if self.get('wallet_type') == 'imported':
            addresses = self.get('addresses')
            assert isinstance(addresses, dict)
            addresses_new = dict()
            for address, details in addresses.items():
                if not bitcoin.is_address(address):
                    remove_address(address)
                    continue
                if details is None:
                    addresses_new[address] = {}
                else:
                    addresses_new[address] = details
            self.put('addresses', addresses_new)

        self.put('seed_version', 16)

    def _convert_version_17(self):
        # delete pruned_txo; construct spent_outpoints
        if not self._is_upgrade_method_needed(16, 16):
            return

        self.put('pruned_txo', None)

        transactions = self.get('transactions', {})  # txid -> raw_tx
        spent_outpoints = defaultdict(dict)
        for txid, raw_tx in transactions.items():
            tx = Transaction(raw_tx)
            for txin in tx.inputs():
                if txin.is_coinbase_input():
                    continue
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                spent_outpoints[prevout_hash][str(prevout_n)] = txid
        self.put('spent_outpoints', spent_outpoints)

        tokens = self.get('tokens', {})  # contractAddr_bindAddr -> [name, symbol, decimals, balance]
        new_tokens = {}
        for key, value in tokens.items():
            contract_addr, bind_addr = key.split('_')
            new_token = Token(contract_addr, bind_addr, value[0], value[1], value[2], value[3])
            new_tokens[new_token.get_key()] = new_token
        self.put('tokens', new_tokens)

        self.put('seed_version', 17)

    def _convert_version_18(self):
        # delete verified_tx3 as its structure changed
        if not self._is_upgrade_method_needed(17, 17):
            return
        self.put('verified_tx3', None)
        self.put('seed_version', 18)

    def _convert_version_19(self):
        # delete tx_fees as its structure changed
        if not self._is_upgrade_method_needed(18, 18):
            return
        self.put('tx_fees', None)
        self.put('seed_version', 19)

    def _convert_version_20(self):
        # store 'derivation' (prefix) and 'root_fingerprint' in all xpub-based keystores.
        # store explicit None values if we cannot retroactively determine them
        if not self._is_upgrade_method_needed(19, 19):
            return

        from .bip32 import BIP32Node, convert_bip32_intpath_to_strpath
        # note: This upgrade method reimplements bip32.root_fp_and_der_prefix_from_xkey.
        #       This is done deliberately, to avoid introducing that method as a dependency to this upgrade.
        for ks_name in ('keystore', *['x{}/'.format(i) for i in range(1, 16)]):
            ks = self.get(ks_name, None)
            if ks is None: continue
            xpub = ks.get('xpub', None)
            if xpub is None: continue
            bip32node = BIP32Node.from_xkey(xpub)
            # derivation prefix
            derivation_prefix = ks.get('derivation', None)
            if derivation_prefix is None:
                assert bip32node.depth >= 0, bip32node.depth
                if bip32node.depth == 0:
                    derivation_prefix = 'm'
                elif bip32node.depth == 1:
                    child_number_int = int.from_bytes(bip32node.child_number, 'big')
                    derivation_prefix = convert_bip32_intpath_to_strpath([child_number_int])
                ks['derivation'] = derivation_prefix
            # root fingerprint
            root_fingerprint = ks.get('ckcc_xfp', None)
            if root_fingerprint is not None:
                root_fingerprint = root_fingerprint.to_bytes(4, byteorder="little", signed=False).hex().lower()
            if root_fingerprint is None:
                if bip32node.depth == 0:
                    root_fingerprint = bip32node.calc_fingerprint_of_this_node().hex().lower()
                elif bip32node.depth == 1:
                    root_fingerprint = bip32node.fingerprint.hex()
            ks['root_fingerprint'] = root_fingerprint
            ks.pop('ckcc_xfp', None)
            self.put(ks_name, ks)

        self.put('seed_version', 20)

    def _convert_version_21(self):
        if not self._is_upgrade_method_needed(20, 20):
            return
        channels = self.get('channels')
        if channels:
            for channel in channels:
                channel['state'] = 'OPENING'
            self.put('channels', channels)
        self.put('seed_version', 21)

    def _convert_version_22(self):
        # construct prevouts_by_scripthash
        if not self._is_upgrade_method_needed(21, 21):
            return

        from .bitcoin import script_to_scripthash
        transactions = self.get('transactions', {})  # txid -> raw_tx
        prevouts_by_scripthash = defaultdict(list)
        for txid, raw_tx in transactions.items():
            tx = Transaction(raw_tx)
            for idx, txout in enumerate(tx.outputs()):
                outpoint = f"{txid}:{idx}"
                scripthash = script_to_scripthash(txout.scriptpubkey.hex())
                prevouts_by_scripthash[scripthash].append((outpoint, txout.value))
        self.put('prevouts_by_scripthash', prevouts_by_scripthash)

        self.put('seed_version', 22)

    def _convert_version_23(self):
        if not self._is_upgrade_method_needed(22, 22):
            return
        channels = self.get('channels', [])
        LOCAL = 1
        REMOTE = -1
        for c in channels:
            # move revocation store from remote_config
            r = c['remote_config'].pop('revocation_store')
            c['revocation_store'] = r
            # convert fee updates
            log = c.get('log', {})
            for sub in LOCAL, REMOTE:
                l = log[str(sub)]['fee_updates']
                d = {}
                for i, fu in enumerate(l):
                    d[str(i)] = {
                        'rate':fu['rate'],
                        'ctn_local':fu['ctns'][str(LOCAL)],
                        'ctn_remote':fu['ctns'][str(REMOTE)]
                    }
                log[str(int(sub))]['fee_updates'] = d
        self.data['channels'] = channels

        self.data['seed_version'] = 23

    def _convert_version_24(self):
        if not self._is_upgrade_method_needed(23, 23):
            return
        channels = self.get('channels', [])
        for c in channels:
            # convert revocation store to dict
            r = c['revocation_store']
            d = {}
            for i in range(49):
                v = r['buckets'][i]
                if v is not None:
                    d[str(i)] = v
            r['buckets'] = d
            c['revocation_store'] = r
        # convert channels to dict
        self.data['channels'] = { x['channel_id']: x for x in channels }
        # convert txi & txo
        txi = self.get('txi', {})
        for tx_hash, d in txi.items():
            d2 = {}
            for addr, l in d.items():
                d2[addr] = {}
                for ser, v in l:
                    d2[addr][ser] = v
            txi[tx_hash] = d2
        self.data['txi'] = txi
        txo = self.get('txo', {})
        for tx_hash, d in txo.items():
            d2 = {}
            for addr, l in d.items():
                d2[addr] = {}
                for n, v, cb in l:
                    d2[addr][str(n)] = (v, cb)
            txo[tx_hash] = d2
        self.data['txo'] = txo

        self.data['seed_version'] = 24

    def _convert_version_25(self):
        if not self._is_upgrade_method_needed(24, 24):
            return
        # add 'type' field to onchain requests
        requests = self.data.get('payment_requests', {})
        for k, r in list(requests.items()):
            if r.get('address') == k:
                requests[k] = {
                    'address': r['address'],
                    'amount': r.get('amount'),
                    'exp': r.get('exp'),
                    'id': r.get('id'),
                    'memo': r.get('memo'),
                    'time': r.get('time'),
                    'type': PR_TYPE_ONCHAIN,
                }
        # convert bip70 invoices
        invoices = self.data.get('invoices', {})
        for k, r in list(invoices.items()):
            data = r.get("hex")
            if data:
                pr = PaymentRequest(bytes.fromhex(data))
                if pr.id != k:
                    continue
                invoices[k] = {
                    'type': PR_TYPE_ONCHAIN,
                    'amount': pr.get_amount(),
                    'bip70': data,
                    'exp': pr.get_expiration_date() - pr.get_time(),
                    'id': pr.id,
                    'message': pr.get_memo(),
                    'outputs': [x.to_legacy_tuple() for x in pr.get_outputs()],
                    'time': pr.get_time(),
                    'requestor': pr.get_requestor(),
                }
        self.data['seed_version'] = 25

    def _convert_version_26(self):
        if not self._is_upgrade_method_needed(25, 25):
            return
        channels = self.data.get('channels', {})
        channel_timestamps = self.data.pop('lightning_channel_timestamps', {})
        for channel_id, c in channels.items():
            item = channel_timestamps.get(channel_id)
            if item:
                funding_txid, funding_height, funding_timestamp, closing_txid, closing_height, closing_timestamp = item
                if funding_txid:
                    c['funding_height'] = funding_txid, funding_height, funding_timestamp
                if closing_txid:
                    c['closing_height'] = closing_txid, closing_height, closing_timestamp
        self.data['seed_version'] = 26

    def _convert_version_27(self):
        if not self._is_upgrade_method_needed(26, 26):
            return
        channels = self.data.get('channels', {})
        for channel_id, c in channels.items():
            c['local_config']['htlc_minimum_msat'] = 1
        self.data['seed_version'] = 27

    def _convert_version_28(self):
        if not self._is_upgrade_method_needed(27, 27):
            return
        channels = self.data.get('channels', {})
        for channel_id, c in channels.items():
            c['local_config']['channel_seed'] = None
        self.data['seed_version'] = 28

    def _convert_version_29(self):
        if not self._is_upgrade_method_needed(28, 28):
            return
        requests = self.data.get('payment_requests', {})
        invoices = self.data.get('invoices', {})
        for d in [invoices, requests]:
            for key, r in list(d.items()):
                _type = r.get('type', 0)
                item = {
                    'type': _type,
                    'message': r.get('message') or r.get('memo', ''),
                    'amount': r.get('amount'),
                    'exp': r.get('exp') or 0,
                    'time': r.get('time', 0),
                }
                if _type == PR_TYPE_ONCHAIN:
                    address = r.pop('address', None)
                    if address:
                        outputs = [(0, address, r.get('amount'))]
                    else:
                        outputs = r.get('outputs')
                    item.update({
                        'outputs': outputs,
                        'id': r.get('id'),
                        'bip70': r.get('bip70'),
                        'requestor': r.get('requestor'),
                    })
                else:
                    item.update({
                        'rhash': r['rhash'],
                        'invoice': r['invoice'],
                    })
                d[key] = item
        self.data['seed_version'] = 29

    def _convert_version_30(self):
        if not self._is_upgrade_method_needed(29, 29):
            return

        from .invoices import PR_TYPE_ONCHAIN, PR_TYPE_LN
        requests = self.data.get('payment_requests', {})
        invoices = self.data.get('invoices', {})
        for d in [invoices, requests]:
            for key, item in list(d.items()):
                _type = item['type']
                if _type == PR_TYPE_ONCHAIN:
                    item['amount_sat'] = item.pop('amount')
                elif _type == PR_TYPE_LN:
                    amount_sat = item.pop('amount')
                    item['amount_msat'] = 1000 * amount_sat if amount_sat is not None else None
                    item.pop('exp')
                    item.pop('message')
                    item.pop('rhash')
                    item.pop('time')
                else:
                    raise Exception(f"unknown invoice type: {_type}")
        self.data['seed_version'] = 30

    def _convert_version_31(self):
        if not self._is_upgrade_method_needed(30, 30):
            return

        from .invoices import PR_TYPE_ONCHAIN
        requests = self.data.get('payment_requests', {})
        invoices = self.data.get('invoices', {})
        for d in [invoices, requests]:
            for key, item in list(d.items()):
                if item['type'] == PR_TYPE_ONCHAIN:
                    item['amount_sat'] = item['amount_sat'] or 0
                    item['exp'] = item['exp'] or 0
                    item['time'] = item['time'] or 0
        self.data['seed_version'] = 31

    def _convert_version_32(self):
        if not self._is_upgrade_method_needed(31, 31):
            return

        from .invoices import PR_TYPE_ONCHAIN
        invoices_old = self.data.get('invoices', {})
        invoices_new = {k: item for k, item in invoices_old.items()
                        if not (item['type'] == PR_TYPE_ONCHAIN and item['outputs'] is None)}
        self.data['invoices'] = invoices_new
        self.data['seed_version'] = 32

    def _convert_imported(self):
        if not self._is_upgrade_method_needed(0, 13):
            return

        # '/x' is the internal ID for imported accounts
        d = self.get('accounts', {}).get('/x', {}).get('imported',{})
        if not d:
            return False
        addresses = []
        keypairs = {}
        for addr, v in d.items():
            pubkey, privkey = v
            if privkey:
                keypairs[pubkey] = privkey
            else:
                addresses.append(addr)
        if addresses and keypairs:
            raise WalletFileException('mixed addresses and privkeys')
        elif addresses:
            self.put('addresses', addresses)
            self.put('accounts', None)
        elif keypairs:
            self.put('wallet_type', 'standard')
            self.put('key_type', 'imported')
            self.put('keypairs', keypairs)
            self.put('accounts', None)
        else:
            raise WalletFileException('no addresses or privkeys')

    def _convert_account(self):
        if not self._is_upgrade_method_needed(0, 13):
            return
        self.put('accounts', None)

    def _is_upgrade_method_needed(self, min_version, max_version):
        assert min_version <= max_version
        cur_version = self.get_seed_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise WalletFileException(
                'storage upgrade: unexpected version {} (should be {}-{})'
                .format(cur_version, min_version, max_version))
        else:
            return True

    @locked
    def get_seed_version(self):
        seed_version = self.get('seed_version')
        if not seed_version:
            seed_version = OLD_SEED_VERSION if len(self.get('master_public_key','')) == 128 else NEW_SEED_VERSION
        if seed_version > FINAL_SEED_VERSION:
            raise WalletFileException('This version of Electrum is too old to open this wallet.\n'
                                      '(highest supported storage version: {}, version of this file: {})'
                                      .format(FINAL_SEED_VERSION, seed_version))
        if seed_version==14 and self.get('seed_type') == 'segwit':
            self._raise_unsupported_version(seed_version)
        if seed_version >=12:
            return seed_version
        if seed_version not in [OLD_SEED_VERSION, NEW_SEED_VERSION]:
            self._raise_unsupported_version(seed_version)
        return seed_version

    def _raise_unsupported_version(self, seed_version):
        msg = f"Your wallet has an unsupported seed version: {seed_version}."
        if seed_version in [5, 7, 8, 9, 10, 14]:
            msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
        if seed_version == 6:
            # version 1.9.8 created v6 wallets when an incorrect seed was entered in the restore dialog
            msg += '\n\nThis file was created because of a bug in version 1.9.8.'
            if self.get('master_public_keys') is None and self.get('master_private_keys') is None and self.get('imported_keys') is None:
                # pbkdf2 (at that time an additional dependency) was not included with the binaries, and wallet creation aborted.
                msg += "\nIt does not contain any keys, and can safely be removed."
            else:
                # creation was complete if electrum was run from source
                msg += "\nPlease open this file with Electrum 1.9.8, and move your coins to a new wallet."
        raise WalletFileException(msg)

    @locked
    def get_txi_addresses(self, tx_hash: str) -> List[str]:
        """Returns list of is_mine addresses that appear as inputs in tx."""
        assert isinstance(tx_hash, str)
        return list(self.txi.get(tx_hash, {}).keys())

    @locked
    def get_txo_addresses(self, tx_hash: str) -> List[str]:
        """Returns list of is_mine addresses that appear as outputs in tx."""
        assert isinstance(tx_hash, str)
        return list(self.txo.get(tx_hash, {}).keys())

    @locked
    def get_txi_addr(self, tx_hash: str, address: str) -> Iterable[Tuple[str, int]]:
        """Returns an iterable of (prev_outpoint, value)."""
        assert isinstance(tx_hash, str)
        assert isinstance(address, str)
        d = self.txi.get(tx_hash, {}).get(address, {})
        return list(d.items())

    @locked
    def get_txo_addr(self, tx_hash: str, address: str) -> Dict[int, Tuple[int, bool]]:
        """Returns a dict: output_index -> (value, is_coinbase)."""
        assert isinstance(tx_hash, str)
        assert isinstance(address, str)
        d = self.txo.get(tx_hash, {}).get(address, {})
        return {int(n): (v, cb) for (n, (v, cb)) in d.items()}

    @modifier
    def add_txi_addr(self, tx_hash: str, addr: str, ser: str, v: int) -> None:
        assert isinstance(tx_hash, str)
        assert isinstance(addr, str)
        assert isinstance(ser, str)
        assert isinstance(v, int)
        if tx_hash not in self.txi:
            self.txi[tx_hash] = {}
        d = self.txi[tx_hash]
        if addr not in d:
            d[addr] = {}
        d[addr][ser] = v

    @modifier
    def add_txo_addr(self, tx_hash: str, addr: str, n: Union[int, str], v: int, is_coinbase: bool) -> None:
        n = str(n)
        assert isinstance(tx_hash, str)
        assert isinstance(addr, str)
        assert isinstance(n, str)
        assert isinstance(v, int)
        assert isinstance(is_coinbase, bool)
        if tx_hash not in self.txo:
            self.txo[tx_hash] = {}
        d = self.txo[tx_hash]
        if addr not in d:
            d[addr] = {}
        d[addr][n] = (v, is_coinbase)

    @locked
    def list_txi(self) -> Sequence[str]:
        return list(self.txi.keys())

    @locked
    def list_txo(self) -> Sequence[str]:
        return list(self.txo.keys())

    @modifier
    def remove_txi(self, tx_hash: str) -> None:
        assert isinstance(tx_hash, str)
        self.txi.pop(tx_hash, None)

    @modifier
    def remove_txo(self, tx_hash: str) -> None:
        assert isinstance(tx_hash, str)
        self.txo.pop(tx_hash, None)

    @locked
    def list_spent_outpoints(self) -> Sequence[Tuple[str, str]]:
        return [(h, n)
                for h in self.spent_outpoints.keys()
                for n in self.get_spent_outpoints(h)
        ]

    @locked
    def get_spent_outpoints(self, prevout_hash: str) -> Sequence[str]:
        assert isinstance(prevout_hash, str)
        return list(self.spent_outpoints.get(prevout_hash, {}).keys())

    @locked
    def get_spent_outpoint(self, prevout_hash: str, prevout_n: Union[int, str]) -> Optional[str]:
        assert isinstance(prevout_hash, str)
        prevout_n = str(prevout_n)
        return self.spent_outpoints.get(prevout_hash, {}).get(prevout_n)

    @modifier
    def remove_spent_outpoint(self, prevout_hash: str, prevout_n: Union[int, str]) -> None:
        assert isinstance(prevout_hash, str)
        prevout_n = str(prevout_n)
        self.spent_outpoints[prevout_hash].pop(prevout_n, None)
        if not self.spent_outpoints[prevout_hash]:
            self.spent_outpoints.pop(prevout_hash)

    @modifier
    def set_spent_outpoint(self, prevout_hash: str, prevout_n: Union[int, str], tx_hash: str) -> None:
        assert isinstance(prevout_hash, str)
        assert isinstance(tx_hash, str)
        prevout_n = str(prevout_n)
        if prevout_hash not in self.spent_outpoints:
            self.spent_outpoints[prevout_hash] = {}
        self.spent_outpoints[prevout_hash][prevout_n] = tx_hash

    @modifier
    def add_prevout_by_scripthash(self, scripthash: str, *, prevout: TxOutpoint, value: int) -> None:
        assert isinstance(scripthash, str)
        assert isinstance(prevout, TxOutpoint)
        assert isinstance(value, int)
        if scripthash not in self._prevouts_by_scripthash:
            self._prevouts_by_scripthash[scripthash] = set()
        self._prevouts_by_scripthash[scripthash].add((prevout.to_str(), value))

    @modifier
    def remove_prevout_by_scripthash(self, scripthash: str, *, prevout: TxOutpoint, value: int) -> None:
        assert isinstance(scripthash, str)
        assert isinstance(prevout, TxOutpoint)
        assert isinstance(value, int)
        self._prevouts_by_scripthash[scripthash].discard((prevout.to_str(), value))
        if not self._prevouts_by_scripthash[scripthash]:
            self._prevouts_by_scripthash.pop(scripthash)

    @locked
    def get_prevouts_by_scripthash(self, scripthash: str) -> Set[Tuple[TxOutpoint, int]]:
        assert isinstance(scripthash, str)
        prevouts_and_values = self._prevouts_by_scripthash.get(scripthash, set())
        return {(TxOutpoint.from_str(prevout), value) for prevout, value in prevouts_and_values}

    @modifier
    def add_transaction(self, tx_hash: str, tx: Transaction) -> None:
        assert isinstance(tx_hash, str)
        assert isinstance(tx, Transaction), tx
        # note that tx might be a PartialTransaction
        if not tx_hash:
            raise Exception("trying to add tx to db without txid")
        if tx_hash != tx.txid():
            raise Exception(f"trying to add tx to db with inconsistent txid: {tx_hash} != {tx.txid()}")
        # don't allow overwriting complete tx with partial tx
        tx_we_already_have = self.transactions.get(tx_hash, None)
        if tx_we_already_have is None or isinstance(tx_we_already_have, PartialTransaction):
            self.transactions[tx_hash] = tx

    @modifier
    def remove_transaction(self, tx_hash: str) -> Optional[Transaction]:
        assert isinstance(tx_hash, str)
        return self.transactions.pop(tx_hash, None)

    @locked
    def get_transaction(self, tx_hash: Optional[str]) -> Optional[Transaction]:
        if tx_hash is None:
            return None
        assert isinstance(tx_hash, str)
        return self.transactions.get(tx_hash)

    @locked
    def list_transactions(self) -> Sequence[str]:
        return list(self.transactions.keys())

    @locked
    def get_history(self) -> Sequence[str]:
        return list(self.history.keys())

    def is_addr_in_history(self, addr: str) -> bool:
        # does not mean history is non-empty!
        assert isinstance(addr, str)
        return addr in self.history

    @locked
    def get_addr_history(self, addr: str) -> Sequence[Tuple[str, int]]:
        assert isinstance(addr, str)
        return self.history.get(addr, [])

    @modifier
    def set_addr_history(self, addr: str, hist) -> None:
        assert isinstance(addr, str)
        self.history[addr] = hist

    @modifier
    def remove_addr_history(self, addr: str) -> None:
        assert isinstance(addr, str)
        self.history.pop(addr, None)

    @locked
    def list_verified_tx(self) -> Sequence[str]:
        return list(self.verified_tx.keys())

    @locked
    def get_verified_tx(self, txid: str) -> Optional[TxMinedInfo]:
        assert isinstance(txid, str)
        if txid not in self.verified_tx:
            return None
        height, timestamp, txpos, header_hash = self.verified_tx[txid]
        return TxMinedInfo(height=height,
                           conf=None,
                           timestamp=timestamp,
                           txpos=txpos,
                           header_hash=header_hash)

    @modifier
    def add_verified_tx(self, txid: str, info: TxMinedInfo):
        assert isinstance(txid, str)
        assert isinstance(info, TxMinedInfo)
        self.verified_tx[txid] = (info.height, info.timestamp, info.txpos, info.header_hash)

    @modifier
    def remove_verified_tx(self, txid: str):
        assert isinstance(txid, str)
        self.verified_tx.pop(txid, None)

    def is_in_verified_tx(self, txid: str) -> bool:
        assert isinstance(txid, str)
        return txid in self.verified_tx

    @modifier
    def add_tx_fee_from_server(self, txid: str, fee_sat: Optional[int]) -> None:
        assert isinstance(txid, str)
        # note: when called with (fee_sat is None), rm currently saved value
        if txid not in self.tx_fees:
            self.tx_fees[txid] = TxFeesValue()
        tx_fees_value = self.tx_fees[txid]
        if tx_fees_value.is_calculated_by_us:
            return
        self.tx_fees[txid] = tx_fees_value._replace(fee=fee_sat, is_calculated_by_us=False)

    @modifier
    def add_tx_fee_we_calculated(self, txid: str, fee_sat: Optional[int]) -> None:
        assert isinstance(txid, str)
        if fee_sat is None:
            return
        assert isinstance(fee_sat, int)
        if txid not in self.tx_fees:
            self.tx_fees[txid] = TxFeesValue()
        self.tx_fees[txid] = self.tx_fees[txid]._replace(fee=fee_sat, is_calculated_by_us=True)

    @locked
    def get_tx_fee(self, txid: str, *, trust_server: bool = False) -> Optional[int]:
        assert isinstance(txid, str)
        """Returns tx_fee."""
        tx_fees_value = self.tx_fees.get(txid)
        if tx_fees_value is None:
            return None
        if not trust_server and not tx_fees_value.is_calculated_by_us:
            return None
        return tx_fees_value.fee

    @modifier
    def add_num_inputs_to_tx(self, txid: str, num_inputs: int) -> None:
        assert isinstance(txid, str)
        assert isinstance(num_inputs, int)
        if txid not in self.tx_fees:
            self.tx_fees[txid] = TxFeesValue()
        self.tx_fees[txid] = self.tx_fees[txid]._replace(num_inputs=num_inputs)

    @locked
    def get_num_all_inputs_of_tx(self, txid: str) -> Optional[int]:
        assert isinstance(txid, str)
        tx_fees_value = self.tx_fees.get(txid)
        if tx_fees_value is None:
            return None
        return tx_fees_value.num_inputs

    @locked
    def get_num_ismine_inputs_of_tx(self, txid: str) -> int:
        assert isinstance(txid, str)
        txins = self.txi.get(txid, {})
        return sum([len(tupls) for addr, tupls in txins.items()])

    @modifier
    def remove_tx_fee(self, txid: str) -> None:
        assert isinstance(txid, str)
        self.tx_fees.pop(txid, None)

    @locked
    def get_dict(self, name) -> dict:
        # Warning: interacts un-intuitively with 'put': certain parts
        # of 'data' will have pointers saved as separate variables.
        if name not in self.data:
            self.data[name] = {}
        return self.data[name]

    @locked
    def num_change_addresses(self) -> int:
        return len(self.change_addresses)

    @locked
    def num_receiving_addresses(self) -> int:
        return len(self.receiving_addresses)

    @locked
    def get_change_addresses(self, *, slice_start=None, slice_stop=None) -> List[str]:
        # note: slicing makes a shallow copy
        return self.change_addresses[slice_start:slice_stop]

    @locked
    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None) -> List[str]:
        # note: slicing makes a shallow copy
        return self.receiving_addresses[slice_start:slice_stop]

    @modifier
    def add_change_address(self, addr: str) -> None:
        assert isinstance(addr, str)
        self._addr_to_addr_index[addr] = (1, len(self.change_addresses))
        self.change_addresses.append(addr)

    @modifier
    def add_receiving_address(self, addr: str) -> None:
        assert isinstance(addr, str)
        self._addr_to_addr_index[addr] = (0, len(self.receiving_addresses))
        self.receiving_addresses.append(addr)

    @locked
    def get_address_index(self, address: str) -> Optional[Sequence[int]]:
        assert isinstance(address, str)
        return self._addr_to_addr_index.get(address)

    @modifier
    def add_imported_address(self, addr: str, d: dict) -> None:
        assert isinstance(addr, str)
        self.imported_addresses[addr] = d

    @modifier
    def remove_imported_address(self, addr: str) -> None:
        assert isinstance(addr, str)
        self.imported_addresses.pop(addr)

    @locked
    def has_imported_address(self, addr: str) -> bool:
        assert isinstance(addr, str)
        return addr in self.imported_addresses

    @locked
    def get_imported_addresses(self) -> Sequence[str]:
        return list(sorted(self.imported_addresses.keys()))

    @locked
    def get_imported_address(self, addr: str) -> Optional[dict]:
        assert isinstance(addr, str)
        return self.imported_addresses.get(addr)

    def load_addresses(self, wallet_type):
        """ called from Abstract_Wallet.__init__ """
        if wallet_type == 'imported':
            self.imported_addresses = self.get_dict('addresses')  # type: Dict[str, dict]
        else:
            self.get_dict('addresses')
            for name in ['receiving', 'change']:
                if name not in self.data['addresses']:
                    self.data['addresses'][name] = []
            self.change_addresses = self.data['addresses']['change']
            self.receiving_addresses = self.data['addresses']['receiving']
            self._addr_to_addr_index = {}  # type: Dict[str, Sequence[int]]  # key: address, value: (is_change, index)
            for i, addr in enumerate(self.receiving_addresses):
                self._addr_to_addr_index[addr] = (0, i)
            for i, addr in enumerate(self.change_addresses):
                self._addr_to_addr_index[addr] = (1, i)

    @profiler
    def _load_transactions(self):
        self.data = StoredDict(self.data, self, [])
        # references in self.data
        # TODO make all these private
        # txid -> address -> prev_outpoint -> value
        self.txi = self.get_dict('txi')                          # type: Dict[str, Dict[str, Dict[str, int]]]
        # txid -> address -> output_index -> (value, is_coinbase)
        self.txo = self.get_dict('txo')                          # type: Dict[str, Dict[str, Dict[str, Tuple[int, bool]]]]
        self.transactions = self.get_dict('transactions')        # type: Dict[str, Transaction]
        self.spent_outpoints = self.get_dict('spent_outpoints')  # txid -> output_index -> next_txid
        self.history = self.get_dict('addr_history')             # address -> list of (txid, height)
        self.verified_tx = self.get_dict('verified_tx3')         # txid -> (height, timestamp, txpos, header_hash)
        self.tx_fees = self.get_dict('tx_fees')                  # type: Dict[str, TxFeesValue]
        # scripthash -> set of (outpoint, value)
        self._prevouts_by_scripthash = self.get_dict('prevouts_by_scripthash')  # type: Dict[str, Set[Tuple[str, int]]]
        # remove unreferenced tx
        for tx_hash in list(self.transactions.keys()):
            if not self.get_txi_addresses(tx_hash) and not self.get_txo_addresses(tx_hash):
                self.logger.info(f"removing unreferenced tx: {tx_hash}")
                self.transactions.pop(tx_hash)
        # remove unreferenced outpoints
        for prevout_hash in self.spent_outpoints.keys():
            d = self.spent_outpoints[prevout_hash]
            for prevout_n, spending_txid in list(d.items()):
                if spending_txid not in self.transactions:
                    self.logger.info("removing unreferenced spent outpoint")
                    d.pop(prevout_n)

        self.tokens = self.get_dict('tokens')
        # contract_addr + '_' + b58addr -> list(txid, height, log_index)
        self.token_history = self.get_dict('addr_token_history')
        # txid -> tx receipt
        self.tx_receipt = self.get_dict('tx_receipt')
        # txid -> raw tx
        self.token_txs = self.get_dict('token_txs')
        self.smart_contracts = self.get_dict('smart_contracts')
        self.delegations = self.get_dict('delegations')

        if self.token_history:
            token_hist_txids = [x2[0] for x2 in reduce(lambda x1, y1: x1+y1, self.token_history.values())]
        else:
            token_hist_txids = []
        for tx_hash, raw in self.token_txs.items():
            if tx_hash in token_hist_txids:
                tx = Transaction(raw)
                self.token_txs[tx_hash] = tx

    @modifier
    def set_token(self, token: Token):
        self.tokens[token.get_key()] = token

    @modifier
    def delete_token(self, key: str):
        self.tokens.pop(key, None)
        self.token_history.pop(key, None)

    @locked
    def get_token(self, key: str) -> Optional[Token]:
        return Token(*self.tokens.get(key))

    @locked
    def list_tokens(self) -> list:
        return list(self.tokens.keys())

    @modifier
    def set_token_history(self, key: str, hist: list):
        self.token_history[key] = hist

    @modifier
    def delete_token_history(self, key: str):
        self.token_history.pop(key, None)

    @locked
    def get_token_history(self, key: str) -> list:
        return self.token_history.get(key, [])

    @locked
    def list_token_histories(self) -> list:
        return list(self.token_history.keys())

    @modifier
    def set_token_tx(self, txid: str, raw: str):
        self.token_txs[txid] = raw

    @modifier
    def delete_token_tx(self, txid: str):
        self.token_txs.pop(txid, None)

    @locked
    def get_token_tx(self, txid: str):
        return self.token_txs.get(txid)

    @locked
    def list_token_txs(self) -> list:
        return list(self.token_txs.keys())

    @modifier
    def set_tx_receipt(self, txid: str, receipt: list):
        self.tx_receipt[txid] = receipt

    @modifier
    def delete_tx_receipt(self, txid: str):
        return self.tx_receipt.pop(txid, None)

    @locked
    def get_tx_receipt(self, txid: str) -> list:
        return self.tx_receipt.get(txid, [])

    @locked
    def list_tx_receipts(self) -> list:
        return list(self.tx_receipt.keys())

    @modifier
    def set_delegation(self, dele: Delegation):
        self.delegations[dele.addr] = [dele.staker, dele.fee, dele.pod]

    @modifier
    def delete_delegation(self, addr: str):
        self.delegations.pop(addr, None)

    @locked
    def get_delegation(self, addr: str) -> Optional[Delegation]:
        dele = self.delegations.get(addr, [])
        if len(dele) != 3:
            self.delete_delegation(addr)
            return None
        return Delegation(addr=addr, staker=dele[0], fee=dele[1], pod=dele[2])

    @locked
    def list_delegations(self) -> Sequence[str]:
        return list(self.delegations.keys())

    @modifier
    def clear_history(self):
        self.txi.clear()
        self.txo.clear()
        self.spent_outpoints.clear()
        self.transactions.clear()
        self.history.clear()
        self.verified_tx.clear()
        self.tx_fees.clear()
        self.token_txs.clear()
        self.token_history.clear()
        self.tx_receipt.clear()
        self._prevouts_by_scripthash.clear()

    def _convert_dict(self, path, key, v):
        if key == 'transactions':
            # note: for performance, "deserialize=False" so that we will deserialize these on-demand
            v = dict((k, tx_from_any(x, deserialize=False)) for k, x in v.items())
        if key == 'invoices':
            v = dict((k, Invoice.from_json(x)) for k, x in v.items())
        if key == 'payment_requests':
            v = dict((k, Invoice.from_json(x)) for k, x in v.items())
        elif key == 'adds':
            v = dict((k, UpdateAddHtlc.from_tuple(*x)) for k, x in v.items())
        elif key == 'fee_updates':
            v = dict((k, FeeUpdate(**x)) for k, x in v.items())
        elif key == 'submarine_swaps':
            v = dict((k, SwapData(**x)) for k, x in v.items())
        elif key == 'channel_backups':
            v = dict((k, ChannelBackupStorage(**x)) for k, x in v.items())
        elif key == 'tx_fees':
            v = dict((k, TxFeesValue(*x)) for k, x in v.items())
        elif key == 'prevouts_by_scripthash':
            v = dict((k, {(prevout, value) for (prevout, value) in x}) for k, x in v.items())
        elif key == 'buckets':
            v = dict((k, ShachainElement(bfh(x[0]), int(x[1]))) for k, x in v.items())
        elif key == 'data_loss_protect_remote_pcp':
            v = dict((k, bfh(x)) for k, x in v.items())
        return v

    def _convert_value(self, path, key, v):
        if key == 'local_config':
            v = LocalConfig(**v)
        elif key == 'remote_config':
            v = RemoteConfig(**v)
        elif key == 'constraints':
            v = ChannelConstraints(**v)
        elif key == 'funding_outpoint':
            v = Outpoint(**v)
        return v

    def _should_convert_to_stored_dict(self, key) -> bool:
        if key == 'keystore':
            return False
        multisig_keystore_names = [('x%d/' % i) for i in range(1, 16)]
        if key in multisig_keystore_names:
            return False
        return True

    def write(self, storage: 'WalletStorage'):
        with self.lock:
            self._write(storage)

    def _write(self, storage: 'WalletStorage'):
        if threading.current_thread().daemon:
            self.logger.warning('daemon thread cannot write db')
            return
        if not self.modified():
            return
        storage.write(self.dump())
        self.set_modified(False)

    def is_ready_to_be_used_by_wallet(self):
        return not self.requires_upgrade() and self._called_after_upgrade_tasks

    def split_accounts(self, root_path):
        from .storage import WalletStorage
        out = []
        result = self.get_split_accounts()
        for data in result:
            path = root_path + '.' + data['suffix']
            storage = WalletStorage(path)
            db = WalletDB(json.dumps(data), manual_upgrades=False)
            db._called_after_upgrade_tasks = False
            db.upgrade()
            db.write(storage)
            out.append(path)
        return out

    def get_action(self):
        action = run_hook('get_action', self)
        return action

    def load_plugins(self):
        wallet_type = self.get('wallet_type')
        if wallet_type in plugin_loaders:
            plugin_loaders[wallet_type]()

    def set_keystore_encryption(self, enable):
        self.put('use_encryption', enable)
