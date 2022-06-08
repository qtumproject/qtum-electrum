# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum Developers
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

import asyncio
import threading
import asyncio
import itertools
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple, NamedTuple, Sequence, List

from aiorpcx import TaskGroup

from . import bitcoin, util, constants
from .bitcoin import TYPE_ADDRESS, TYPE_PUBKEY
from .util import profiler, bfh, TxMinedInfo, UnrelatedTransactionException
from .util import profiler, bfh, TxMinedInfo
from .transaction import Transaction, TxOutput, TxInput, PartialTxInput, TxOutpoint, PartialTransaction
from .synchronizer import Synchronizer
from .verifier import SPV
from .blockchain import hash_header
from .i18n import _
from .logging import Logger

if TYPE_CHECKING:
    from .network import Network
    from .wallet_db import WalletDB
    from .bitcoin import Token, Delegation


TX_HEIGHT_FUTURE = -3
TX_HEIGHT_LOCAL = -2
TX_HEIGHT_UNCONF_PARENT = -1
TX_HEIGHT_UNCONFIRMED = 0


class HistoryItem(NamedTuple):
    txid: str
    tx_mined_status: TxMinedInfo
    delta: int
    fee: Optional[int]
    balance: int


class TxWalletDelta(NamedTuple):
    is_relevant: bool  # "related to wallet?"
    is_any_input_ismine: bool
    is_all_input_ismine: bool
    delta: int
    fee: Optional[int]


class AddressSynchronizer(Logger):
    """
    inherited by wallet
    """

    network: Optional['Network']
    synchronizer: Optional['Synchronizer']
    verifier: Optional['SPV']

    def __init__(self, db: 'WalletDB'):
        self.db = db
        self.network = None
        Logger.__init__(self)
        # verifier (SPV) and synchronizer are started in start_network
        self.synchronizer = None
        self.verifier = None
        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()
        self.token_lock = threading.RLock()
        self.delegation_lock = threading.RLock()
        self.future_tx = {}  # type: Dict[str, int]  # txid -> blocks remaining
        # Transactions pending verification.  txid -> tx_height. Access with self.lock.
        self.unverified_tx = defaultdict(int)
        # true when synchronized
        self.up_to_date = False
        # thread local storage for caching stuff
        self.threadlocal_cache = threading.local()

        self._get_addr_balance_cache = {}

        self.load_and_cleanup()

    def with_lock(func):
        def func_wrapper(self: 'AddressSynchronizer', *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def with_transaction_lock(func):
        def func_wrapper(self: 'AddressSynchronizer', *args, **kwargs):
            with self.transaction_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def load_and_cleanup(self):
        self.load_local_history()
        self.check_history()
        self.load_unverified_transactions()
        self.remove_local_transactions_we_dont_have()

    def is_mine(self, address: Optional[str]) -> bool:
        if not address: return False
        return self.db.is_addr_in_history(address)

    def get_addresses(self):
        return sorted(self.db.get_history())

    def get_address_history(self, addr: str) -> Sequence[Tuple[str, int]]:
        """Returns the history for the address, in the format that would be returned by a server.

        Note: The difference between db.get_addr_history and this method is that
        db.get_addr_history stores the response from a server, so it only includes txns
        a server sees, i.e. that does not contain local and future txns.
        """
        h = []
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            related_txns = self._history_local.get(addr, set())
            for tx_hash in related_txns:
                tx_height = self.get_tx_height(tx_hash).height
                h.append((tx_hash, tx_height))
        return h

    def get_address_history_len(self, addr: str) -> int:
        """Return number of transactions where address is involved."""
        return len(self._history_local.get(addr, ()))

    def get_txin_address(self, txin: TxInput) -> Optional[str]:
        if isinstance(txin, PartialTxInput):
            if txin.address:
                return txin.address
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        for addr in self.db.get_txo_addresses(prevout_hash):
            d = self.db.get_txo_addr(prevout_hash, addr)
            if prevout_n in d:
                return addr
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].address
        return None

    def get_txin_value(self, txin: TxInput, *, address: str = None) -> Optional[int]:
        if txin.value_sats() is not None:
            return txin.value_sats()
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        if address is None:
            address = self.get_txin_address(txin)
        if address:
            d = self.db.get_txo_addr(prevout_hash, address)
            try:
                v, cb = d[prevout_n]
                return v
            except KeyError:
                pass
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].value
        return None

    def get_txout_address(self, txo: TxOutput) -> Optional[str]:
        return txo.address

    def load_unverified_transactions(self):
        # review transactions that are in the history
        for addr in self.db.get_history():
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_tx(tx_hash, tx_height)

        # review transactions that are in the token history
        for key in self.db.list_token_histories():
            token_hist = self.db.get_token_history(key)
            for txid, height, log_index in token_hist:
                self.add_unverified_tx(txid, height)

    def start_network(self, network: Optional['Network']) -> None:
        self.network = network
        if self.network is not None:
            self.synchronizer = Synchronizer(self)
            self.verifier = SPV(self.network, self)
            util.register_callback(self.on_blockchain_updated, ['blockchain_updated'])

    def on_blockchain_updated(self, event, *args):
        self._get_addr_balance_cache = {}  # invalidate cache

    async def stop(self):
        if self.network:
            try:
                async with TaskGroup() as group:
                    if self.synchronizer:
                        await group.spawn(self.synchronizer.stop())
                    if self.verifier:
                        await group.spawn(self.verifier.stop())
            finally:
                self.synchronizer = None
                self.verifier = None
                util.unregister_callback(self.on_blockchain_updated)
                self.db.put('stored_height', self.get_local_height())

    def add_address(self, address):
        if not self.db.get_addr_history(address):
            self.db.history[address] = []
            self.set_up_to_date(False)
        if self.synchronizer:
            self.synchronizer.add(address)

    def get_conflicting_transactions(self, tx_hash, tx: Transaction, include_self=False):
        """Returns a set of transaction hashes from the wallet history that are
        directly conflicting with tx, i.e. they have common outpoints being
        spent with tx.

        include_self specifies whether the tx itself should be reported as a
        conflict (if already in wallet history)
        """
        conflicting_txns = set()
        with self.transaction_lock:
            for txin in tx.inputs():
                if txin.is_coinbase_input():
                    continue
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                spending_tx_hash = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                if spending_tx_hash is None:
                    continue
                # this outpoint has already been spent, by spending_tx
                # annoying assert that has revealed several bugs over time:
                assert self.db.get_transaction(spending_tx_hash), "spending tx not in wallet db"
                conflicting_txns |= {spending_tx_hash}
            if tx_hash in conflicting_txns:
                # this tx is already in history, so it conflicts with itself
                if len(conflicting_txns) > 1:
                    raise Exception('Found conflicting transactions already in wallet history.')
                if not include_self:
                    conflicting_txns -= {tx_hash}
            return conflicting_txns

    def add_transaction(self, tx: Transaction, *, allow_unrelated=False) -> bool:
        """Returns whether the tx was successfully added to the wallet history."""
        assert tx, tx
        # note: tx.is_complete() is not necessarily True; tx might be partial
        # but it *needs* to have a txid:
        tx_hash = tx.txid()
        if tx_hash is None:
            raise Exception("cannot add tx without txid to wallet history")
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            # NOTE: returning if tx in self.transactions might seem like a good idea
            # BUT we track is_mine inputs in a txn, and during subsequent calls
            # of add_transaction tx, we might learn of more-and-more inputs of
            # being is_mine, as we roll the gap_limit forward
            is_coinbase = tx.inputs()[0].is_coinbase_input() or tx.outputs()[0].is_coinstake()
            tx_height = self.get_tx_height(tx_hash).height
            if not allow_unrelated:
                # note that during sync, if the transactions are not properly sorted,
                # it could happen that we think tx is unrelated but actually one of the inputs is is_mine.
                # this is the main motivation for allow_unrelated
                is_mine = any([self.is_mine(self.get_txin_address(txin)) for txin in tx.inputs()])
                is_for_me = any([self.is_mine(self.get_txout_address(txo)) for txo in tx.outputs()])
                if not is_mine and not is_for_me:
                    raise UnrelatedTransactionException()
            # Find all conflicting transactions.
            # In case of a conflict,
            #     1. confirmed > mempool > local
            #     2. this new txn has priority over existing ones
            # When this method exits, there must NOT be any conflict, so
            # either keep this txn and remove all conflicting (along with dependencies)
            #     or drop this txn
            conflicting_txns = self.get_conflicting_transactions(tx_hash, tx)
            if conflicting_txns:
                existing_mempool_txn = any(
                    self.get_tx_height(tx_hash2).height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT)
                    for tx_hash2 in conflicting_txns)
                existing_confirmed_txn = any(
                    self.get_tx_height(tx_hash2).height > 0
                    for tx_hash2 in conflicting_txns)
                if existing_confirmed_txn and tx_height <= 0:
                    # this is a non-confirmed tx that conflicts with confirmed txns; drop.
                    return False
                if existing_mempool_txn and tx_height == TX_HEIGHT_LOCAL:
                    # this is a local tx that conflicts with non-local txns; drop.
                    return False
                # keep this txn and remove all conflicting
                to_remove = set()
                to_remove |= conflicting_txns
                for conflicting_tx_hash in conflicting_txns:
                    to_remove |= self.get_depending_transactions(conflicting_tx_hash)
                for tx_hash2 in to_remove:
                    self.remove_transaction(tx_hash2)
            # add inputs
            def add_value_from_prev_output():
                # note: this takes linear time in num is_mine outputs of prev_tx
                addr = self.get_txin_address(txi)
                if addr and self.is_mine(addr):
                    outputs = self.db.get_txo_addr(prevout_hash, addr)
                    try:
                        v, is_cb = outputs[prevout_n]
                    except KeyError:
                        pass
                    else:
                        self.db.add_txi_addr(tx_hash, addr, ser, v)
                        self._get_addr_balance_cache.pop(addr, None)  # invalidate cache
            for txi in tx.inputs():
                if txi.is_coinbase_input():
                    continue
                prevout_hash = txi.prevout.txid.hex()
                prevout_n = txi.prevout.out_idx
                ser = txi.prevout.to_str()
                self.db.set_spent_outpoint(prevout_hash, prevout_n, tx_hash)
                add_value_from_prev_output()
            # add outputs
            for n, txo in enumerate(tx.outputs()):
                v = txo.value
                ser = tx_hash + ':%d'%n
                scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey.hex())
                self.db.add_prevout_by_scripthash(scripthash, prevout=TxOutpoint.from_str(ser), value=v)
                addr = self.get_txout_address(txo)
                if addr and self.is_mine(addr):
                    self.db.add_txo_addr(tx_hash, addr, n, v, is_coinbase)
                    self._get_addr_balance_cache.pop(addr, None)  # invalidate cache
                    # give v to txi that spends me
                    next_tx = self.db.get_spent_outpoint(tx_hash, n)
                    if next_tx is not None:
                        self.db.add_txi_addr(next_tx, addr, ser, v)
                        self._add_tx_to_local_history(next_tx)
            # add to local history
            self._add_tx_to_local_history(tx_hash)
            # save
            self.db.add_transaction(tx_hash, tx)
            self.db.add_num_inputs_to_tx(tx_hash, len(tx.inputs()))
            return True

    def remove_transaction(self, tx_hash: str) -> None:
        def remove_from_spent_outpoints():
            # undo spends in spent_outpoints
            if tx is not None:
                # if we have the tx, this branch is faster
                for txin in tx.inputs():
                    if txin.is_coinbase_input():
                        continue
                    prevout_hash = txin.prevout.txid.hex()
                    prevout_n = txin.prevout.out_idx
                    self.db.remove_spent_outpoint(prevout_hash, prevout_n)
            else:
                # expensive but always works
                for prevout_hash, prevout_n in self.db.list_spent_outpoints():
                    spending_txid = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                    if spending_txid == tx_hash:
                        self.db.remove_spent_outpoint(prevout_hash, prevout_n)

        with self.lock, self.transaction_lock:
            self.logger.info(f"removing tx from history {tx_hash}")
            tx = self.db.remove_transaction(tx_hash)
            remove_from_spent_outpoints()
            self._remove_tx_from_local_history(tx_hash)
            for addr in itertools.chain(self.db.get_txi_addresses(tx_hash), self.db.get_txo_addresses(tx_hash)):
                self._get_addr_balance_cache.pop(addr, None)  # invalidate cache
            self.db.remove_txi(tx_hash)
            self.db.remove_txo(tx_hash)
            self.db.remove_tx_fee(tx_hash)
            self.db.remove_verified_tx(tx_hash)
            self.unverified_tx.pop(tx_hash, None)
            if tx:
                for idx, txo in enumerate(tx.outputs()):
                    scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey.hex())
                    prevout = TxOutpoint(bfh(tx_hash), idx)
                    self.db.remove_prevout_by_scripthash(scripthash, prevout=prevout, value=txo.value)

    def get_depending_transactions(self, tx_hash: str) -> Set[str]:
        """Returns all (grand-)children of tx_hash in this wallet."""
        with self.transaction_lock:
            children = set()
            for n in self.db.get_spent_outpoints(tx_hash):
                other_hash = self.db.get_spent_outpoint(tx_hash, n)
                children.add(other_hash)
                children |= self.get_depending_transactions(other_hash)
            return children

    def receive_tx_callback(self, tx_hash: str, tx: Transaction, tx_height: int) -> None:
        self.add_unverified_tx(tx_hash, tx_height)
        self.add_transaction(tx, allow_unrelated=True)

    def receive_history_callback(self, addr: str, hist, tx_fees: Dict[str, int]):
        with self.lock:
            old_hist = self.get_address_history(addr)
            for tx_hash, height in old_hist:
                if (tx_hash, height) not in hist:
                    # if coinstake, just remove it
                    tx = self.db.get_transaction(tx_hash)
                    if tx.is_coinstake():
                        self.remove_transaction(tx_hash)
                        continue
                    # make tx local
                    self.unverified_tx.pop(tx_hash, None)
                    self.db.remove_verified_tx(tx_hash)
                    if self.verifier:
                        self.verifier.remove_spv_proof_for_tx(tx_hash)

            self.db.set_addr_history(addr, hist)

        for tx_hash, tx_height in hist:
            # add it in case it was previously unconfirmed
            self.add_unverified_tx(tx_hash, tx_height)
            # if addr is new, we have to recompute txi and txo
            tx = self.db.get_transaction(tx_hash)
            if tx is None:
                continue
            self.add_transaction(tx, allow_unrelated=True)

        # Store fees
        for tx_hash, fee_sat in tx_fees.items():
            self.db.add_tx_fee_from_server(tx_hash, fee_sat)

    @profiler
    def load_local_history(self):
        self._history_local = {}  # type: Dict[str, Set[str]]  # address -> set(txid)
        self._address_history_changed_events = defaultdict(asyncio.Event)  # address -> Event
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            self._add_tx_to_local_history(txid)

    @profiler
    def check_history(self):
        hist_addrs_mine = list(filter(lambda k: self.is_mine(k), self.db.get_history()))
        hist_addrs_not_mine = list(filter(lambda k: not self.is_mine(k), self.db.get_history()))
        for addr in hist_addrs_not_mine:
            self.db.remove_addr_history(addr)
        for addr in hist_addrs_mine:
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                if self.db.get_txi_addresses(tx_hash) or self.db.get_txo_addresses(tx_hash):
                    continue
                tx = self.db.get_transaction(tx_hash)
                if tx is not None:
                    self.add_transaction(tx, allow_unrelated=True)

    def remove_local_transactions_we_dont_have(self):
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            tx_height = self.get_tx_height(txid).height
            if tx_height == TX_HEIGHT_LOCAL and not self.db.get_transaction(txid):
                self.remove_transaction(txid)

    def clear_history(self):
        with self.lock:
            with self.transaction_lock:
                self.db.clear_history()
                self._history_local.clear()

    def get_txpos(self, tx_hash):
        """Returns (height, txpos) tuple, even if the tx is unverified."""
        with self.lock:
            verified_tx_mined_info = self.db.get_verified_tx(tx_hash)
            if verified_tx_mined_info:
                return verified_tx_mined_info.height, verified_tx_mined_info.txpos
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return (height, -1) if height > 0 else ((1e9 - height), -1)
            else:
                return (1e9+1, -1)

    def with_local_height_cached(func):
        # get local height only once, as it's relatively expensive.
        # take care that nested calls work as expected
        def f(self, *args, **kwargs):
            orig_val = getattr(self.threadlocal_cache, 'local_height', None)
            self.threadlocal_cache.local_height = orig_val or self.get_local_height()
            try:
                return func(self, *args, **kwargs)
            finally:
                self.threadlocal_cache.local_height = orig_val
        return f

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_history(self, *, domain=None) -> Sequence[HistoryItem]:
        # get domain
        if domain is None:
            domain = self.get_addresses()
        domain = set(domain)
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(int)  # type: Dict[str, int]
        for addr in domain:
            h = self.get_address_history(addr)
            for tx_hash, height in h:
                tx_deltas[tx_hash] += self.get_tx_delta(tx_hash, addr)
        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            delta = tx_deltas[tx_hash]
            tx_mined_status = self.get_tx_height(tx_hash)
            fee = self.get_tx_fee(tx_hash)
            history.append((tx_hash, tx_mined_status, delta, fee))
        history.sort(key = lambda x: self.get_txpos(x[0]), reverse=True)
        # 3. add balance
        c, u, x = self.get_balance(domain)
        balance = c + u + x
        h2 = []
        for tx_hash, tx_mined_status, delta, fee in history:
            h2.append(HistoryItem(txid=tx_hash,
                                  tx_mined_status=tx_mined_status,
                                  delta=delta,
                                  fee=fee,
                                  balance=balance))
            balance -= delta
        h2.reverse()

        if balance != 0:
            raise Exception("wallet.get_history() failed balance sanity-check")

        return h2

    def _add_tx_to_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                cur_hist.add(txid)
                self._history_local[addr] = cur_hist
                self._mark_address_history_changed(addr)

    def _remove_tx_from_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                try:
                    cur_hist.remove(txid)
                except KeyError:
                    pass
                else:
                    self._history_local[addr] = cur_hist

    def _mark_address_history_changed(self, addr: str) -> None:
        # history for this address changed, wake up coroutines:
        self._address_history_changed_events[addr].set()
        # clear event immediately so that coroutines can wait() for the next change:
        self._address_history_changed_events[addr].clear()

    async def wait_for_address_history_to_change(self, addr: str) -> None:
        """Wait until the server tells us about a new transaction related to addr.

        Unconfirmed and confirmed transactions are not distinguished, and so e.g. SPV
        is not taken into account.
        """
        assert self.is_mine(addr), "address needs to be is_mine to be watched"
        await self._address_history_changed_events[addr].wait()

    def add_unverified_tx(self, tx_hash, tx_height):
        if self.db.is_in_verified_tx(tx_hash):
            if tx_height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT):
                with self.lock:
                    self.db.remove_verified_tx(tx_hash)
                if self.verifier:
                    self.verifier.remove_spv_proof_for_tx(tx_hash)
        else:
            with self.lock:
                # tx will be verified only if height > 0
                self.unverified_tx[tx_hash] = tx_height

    def remove_unverified_tx(self, tx_hash, tx_height):
        with self.lock:
            new_height = self.unverified_tx.get(tx_hash)
            if new_height == tx_height:
                self.unverified_tx.pop(tx_hash, None)

    def add_verified_tx(self, tx_hash: str, info: TxMinedInfo):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_tx.pop(tx_hash, None)
            self.db.add_verified_tx(tx_hash, info)
        tx_mined_status = self.get_tx_height(tx_hash)
        util.trigger_callback('verified', self, tx_hash, tx_mined_status)

    def get_unverified_txs(self):
        '''Returns a map from tx hash to transaction height'''
        with self.lock:
            return dict(self.unverified_tx)  # copy

    def undo_verifications(self, blockchain, above_height):
        '''Used by the verifier when a reorg has happened'''
        txs = set()
        with self.lock:
            for tx_hash in self.db.list_verified_tx():
                info = self.db.get_verified_tx(tx_hash)
                tx_height = info.height
                if tx_height > above_height:
                    header = blockchain.read_header(tx_height)
                    if not header or hash_header(header) != info.header_hash:
                        self.db.remove_verified_tx(tx_hash)
                        # NOTE: we should add these txns to self.unverified_tx,
                        # but with what height?
                        # If on the new fork after the reorg, the txn is at the
                        # same height, we will not get a status update for the
                        # address. If the txn is not mined or at a diff height,
                        # we should get a status update. Unless we put tx into
                        # unverified_tx, it will turn into local. So we put it
                        # into unverified_tx with the old height, and if we get
                        # a status update, that will overwrite it.
                        self.unverified_tx[tx_hash] = tx_height
                        txs.add(tx_hash)
        return txs

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        cached_local_height = getattr(self.threadlocal_cache, 'local_height', None)
        if cached_local_height is not None:
            return cached_local_height
        return self.network.get_local_height() if self.network else self.db.get('stored_height', 0)

    def add_future_tx(self, tx: Transaction, num_blocks: int) -> bool:
        assert num_blocks > 0, num_blocks
        with self.lock:
            tx_was_added = self.add_transaction(tx)
            if tx_was_added:
                self.future_tx[tx.txid()] = num_blocks
            return tx_was_added

    def get_tx_height(self, tx_hash: str) -> TxMinedInfo:
        if tx_hash is None:  # ugly backwards compat...
            return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)
        with self.lock:
            verified_tx_mined_info = self.db.get_verified_tx(tx_hash)
            if verified_tx_mined_info:
                conf = max(self.get_local_height() - verified_tx_mined_info.height + 1, 0)
                return verified_tx_mined_info._replace(conf=conf)
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return TxMinedInfo(height=height, conf=0)
            elif tx_hash in self.future_tx:
                num_blocks_remainining = self.future_tx[tx_hash]
                assert num_blocks_remainining > 0, num_blocks_remainining
                return TxMinedInfo(height=TX_HEIGHT_FUTURE, conf=-num_blocks_remainining)
            else:
                # local transaction
                return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)

    def set_up_to_date(self, up_to_date):
        with self.lock:
            status_changed = self.up_to_date != up_to_date
            self.up_to_date = up_to_date
        if self.network:
            self.network.notify('status')
        if status_changed:
            self.logger.info(f'set_up_to_date: {up_to_date}')

    def is_up_to_date(self):
        with self.lock: return self.up_to_date

    def get_history_sync_state_details(self) -> Tuple[int, int]:
        if self.synchronizer:
            return self.synchronizer.num_requests_sent_and_answered()
        else:
            return 0, 0

    @with_transaction_lock
    def get_tx_delta(self, tx_hash: str, address: str) -> int:
        """effect of tx on address"""
        delta = 0
        # subtract the value of coins sent from address
        d = self.db.get_txi_addr(tx_hash, address)
        for n, v in d:
            delta -= v
        # add the value of the coins received at address
        d = self.db.get_txo_addr(tx_hash, address)
        for n, (v, cb) in d.items():
            delta += v
        return delta

    def get_wallet_delta(self, tx: Transaction) -> TxWalletDelta:
        """effect of tx on wallet"""
        is_relevant = False  # "related to wallet?"
        num_input_ismine = 0
        v_in = v_in_mine = v_out = v_out_mine = 0
        with self.lock, self.transaction_lock:
            for txin in tx.inputs():
                addr = self.get_txin_address(txin)
                value = self.get_txin_value(txin, address=addr)
                if self.is_mine(addr):
                    num_input_ismine += 1
                    is_relevant = True
                    assert value is not None
                    v_in_mine += value
                if value is None:
                    v_in = None
                elif v_in is not None:
                    v_in += value
            for txout in tx.outputs():
                v_out += txout.value
                if self.is_mine(txout.address):
                    v_out_mine += txout.value
                    is_relevant = True
        delta = v_out_mine - v_in_mine
        if v_in is not None:
            fee = v_in - v_out
        else:
            fee = None
        if fee is None and isinstance(tx, PartialTransaction):
            fee = tx.get_fee()
        return TxWalletDelta(
            is_relevant=is_relevant,
            is_any_input_ismine=num_input_ismine > 0,
            is_all_input_ismine=num_input_ismine == len(tx.inputs()),
            delta=delta,
            fee=fee,
        )

    def get_tx_fee(self, txid: str) -> Optional[int]:
        """ Returns tx_fee or None. Use server fee only if tx is unconfirmed and not mine"""
        # check if stored fee is available
        fee = self.db.get_tx_fee(txid, trust_server=False)
        if fee is not None:
            return fee
        # delete server-sent fee for confirmed txns
        confirmed = self.get_tx_height(txid).conf > 0
        if confirmed:
            self.db.add_tx_fee_from_server(txid, None)
        # if all inputs are ismine, try to calc fee now;
        # otherwise, return stored value
        num_all_inputs = self.db.get_num_all_inputs_of_tx(txid)
        if num_all_inputs is not None:
            # check if tx is mine
            num_ismine_inputs = self.db.get_num_ismine_inputs_of_tx(txid)
            assert num_ismine_inputs <= num_all_inputs, (num_ismine_inputs, num_all_inputs)
            # trust server if tx is unconfirmed and not mine
            if num_ismine_inputs < num_all_inputs:
                return None if confirmed else self.db.get_tx_fee(txid, trust_server=True)
        # lookup tx and deserialize it.
        # note that deserializing is expensive, hence above hacks
        tx = self.db.get_transaction(txid)
        if not tx:
            return None
        fee = self.get_wallet_delta(tx).fee
        # save result
        self.db.add_tx_fee_we_calculated(txid, fee)
        self.db.add_num_inputs_to_tx(txid, len(tx.inputs()))
        return fee

    def get_addr_io(self, address):
        with self.lock, self.transaction_lock:
            h = self.get_address_history(address)
            received = {}
            sent = {}
            for tx_hash, height in h:
                d = self.db.get_txo_addr(tx_hash, address)
                for n, (v, is_cb) in d.items():
                    received[tx_hash + ':%d'%n] = (height, v, is_cb)
            for tx_hash, height in h:
                l = self.db.get_txi_addr(tx_hash, address)
                for txi, v in l:
                    sent[txi] = height
        return received, sent


    def get_addr_outputs(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        coins, spent = self.get_addr_io(address)
        out = {}
        for prevout_str, v in coins.items():
            tx_height, value, is_cb = v
            prevout = TxOutpoint.from_str(prevout_str)
            utxo = PartialTxInput(prevout=prevout, is_coinbase_output=is_cb)
            utxo._trusted_address = address
            utxo._trusted_value_sats = value
            utxo.block_height = tx_height
            utxo.spent_height = spent.get(prevout_str, None)
            out[prevout] = utxo
        return out

    def get_addr_utxo(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        out = self.get_addr_outputs(address)
        for k, v in list(out.items()):
            if v.spent_height is not None:
                out.pop(k)
        return out

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received, sent = self.get_addr_io(address)
        return sum([v for height, v, is_cb in received.values()])

    @with_local_height_cached
    def get_addr_balance(self, address, *, excluded_coins: Set[str] = None) -> Tuple[int, int, int]:
        """Return the balance of a bitcoin address:
        confirmed and matured, unconfirmed, unmatured
        """
        if not excluded_coins:  # cache is only used if there are no excluded_coins
            cached_value = self._get_addr_balance_cache.get(address)
            if cached_value:
                return cached_value
        if excluded_coins is None:
            excluded_coins = set()
        assert isinstance(excluded_coins, set), f"excluded_coins should be set, not {type(excluded_coins)}"
        received, sent = self.get_addr_io(address)
        c = u = x = 0
        mempool_height = self.get_local_height() + 1  # height of next block
        net = constants.net
        for txo, (tx_height, v, is_cb) in received.items():
            if txo in excluded_coins:
                continue
            if is_cb and tx_height + net.coinbase_maturity(mempool_height) > mempool_height:
                x += v
            elif tx_height > 0:
                c += v
            else:
                u += v
            if txo in sent:
                if sent[txo] > 0:
                    c -= v
                else:
                    u -= v
        result = c, u, x
        # cache result.
        if not excluded_coins:
            # Cache needs to be invalidated if a transaction is added to/
            # removed from history; or on new blocks (maturity...)
            self._get_addr_balance_cache[address] = result
        return result

    @with_local_height_cached
    def get_utxos(self, domain=None, *, excluded_addresses=None,
                  mature_only: bool = False, confirmed_only: bool = False,
                  nonlocal_only: bool = False) -> Sequence[PartialTxInput]:
        coins = []
        if domain is None:
            domain = self.get_addresses()
        domain = set(domain)
        if excluded_addresses:
            domain = set(domain) - set(excluded_addresses)
        mempool_height = self.get_local_height() + 1  # height of next block
        net = constants.net
        for addr in domain:
            utxos = self.get_addr_utxo(addr)
            for utxo in utxos.values():
                if confirmed_only and utxo.block_height <= 0:
                    continue
                if nonlocal_only and utxo.block_height == TX_HEIGHT_LOCAL:
                    continue
                if (mature_only and utxo.is_coinbase_output()
                        and utxo.block_height + net.coinbase_maturity(mempool_height) > mempool_height):
                    continue
                coins.append(utxo)
                continue
        return coins

    def get_balance(self, domain=None, *, excluded_addresses: Set[str] = None,
                    excluded_coins: Set[str] = None) -> Tuple[int, int, int]:
        if domain is None:
            domain = self.get_addresses()
        if excluded_addresses is None:
            excluded_addresses = set()
        assert isinstance(excluded_addresses, set), f"excluded_addresses should be set, not {type(excluded_addresses)}"
        domain = set(domain) - excluded_addresses
        cc = uu = xx = 0
        for addr in domain:
            c, u, x = self.get_addr_balance(addr, excluded_coins=excluded_coins)
            cc += c
            uu += u
            xx += x
        return cc, uu, xx

    def is_used(self, address: str) -> bool:
        return self.get_address_history_len(address) != 0

    def is_empty(self, address: str) -> bool:
        c, u, x = self.get_addr_balance(address)
        return c+u+x == 0

    def synchronize(self):
        pass

    def get_tokens(self):
        return sorted(self.db.list_tokens())

    @profiler
    def check_token_history(self):
        # remove not mine and not subscribe token history
        hist_keys_not_mine = list(filter(lambda k: not self.is_mine(k.split('_')[1]), self.db.get_token_history()))
        hist_keys_not_subscribe = list(filter(lambda k: k not in self.tokens, self.db.get_token_history()))
        for key in set(hist_keys_not_mine).union(hist_keys_not_subscribe):
            hist = self.db.get_token_history(key)
            for txid, height, log_index in hist:
                self.db.delete_token_tx(txid)

    def receive_token_history_callback(self, key, hist):
        with self.token_lock:
            self.db.set_token_history(key, hist)

    def receive_tx_receipt_callback(self, tx_hash, tx_receipt):
        self.add_tx_receipt(tx_hash, tx_receipt)

    def receive_token_tx_callback(self, tx_hash, tx, tx_height):
        self.add_unverified_tx(tx_hash, tx_height)
        self.add_token_transaction(tx_hash, tx)

    def add_tx_receipt(self, tx_hash, tx_receipt):
        assert tx_hash, 'none tx_hash'
        assert tx_receipt, 'empty tx_receipt'
        for contract_call in tx_receipt:
            if not contract_call.get('transactionHash') == tx_hash:
                return
            if not contract_call.get('log'):
                return
        with self.token_lock:
            self.db.set_tx_receipt(tx_hash, tx_receipt)

    def add_token_transaction(self, tx_hash, tx):
        with self.token_lock:
            assert tx.is_complete(), 'incomplete tx'
            self.db.set_token_tx(tx_hash, tx)
            return True

    def add_token(self, token: 'Token'):
        self.db.set_token(token)
        if self.synchronizer:
            self.synchronizer.add_token(token)

    def delete_token(self, key):
        with self.token_lock:
            if key in self.db.list_tokens():
                self.db.delete_token(key)
            if key in self.db.list_token_histories():
                self.db.delete_token_history(key)

    def add_delegation(self, dele: 'Delegation'):
        with self.delegation_lock:
            self.db.set_delegation(dele)

    def delete_delegation(self, address: str):
        with self.delegation_lock:
            if address in self.db.list_delegations():
                self.db.delete_delegation(address)
