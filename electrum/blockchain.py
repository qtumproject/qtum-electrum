# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
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
import math
import threading
import sqlite3
from typing import Optional, Dict, Mapping, Sequence, Union
import time

from . import util
from .bitcoin import hash_encode, int_to_hex, rev_hex, var_int
from .crypto import sha256d
from . import constants
from .util import bfh, unpack_uint16_from, unpack_int32_from, unpack_uint32_from, unpack_int64_from, unpack_uint64_from
from .simple_config import SimpleConfig
from .logging import get_logger, Logger


_logger = get_logger(__name__)

POW_BLOCK_COUNT = 5000
CHUNK_SIZE = 1024
BASIC_HEADER_SIZE = 180  # not include sig
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

POW_TARGET_TIMESPAN = 16 * 60  # bitcoin is 14 * 24 * 60 * 60
POW_TARGET_TIMESPAN_V2 = 4000
POW_TARGET_TIMESPAN_RBT = 1000

POW_TARGET_TIMESPACE = 2 * 64  # bitcoin is 10 * 60
POW_TARGET_TIMESPACE_RBT = 32


class MissingHeader(Exception):
    pass

class InvalidHeader(Exception):
    pass

def serialize_header(header_dict: dict) -> str:
    sig_length = len(header_dict.get('sig')) // 2
    s = int_to_hex(header_dict['version'], 4) \
        + rev_hex(header_dict['prev_block_hash']) \
        + rev_hex(header_dict['merkle_root']) \
        + int_to_hex(int(header_dict['timestamp']), 4) \
        + int_to_hex(int(header_dict['bits']), 4) \
        + int_to_hex(int(header_dict['nonce']), 4) \
        + rev_hex(header_dict.get('hash_state_root')) \
        + rev_hex(header_dict.get('hash_utxo_root')) \
        + rev_hex(header_dict.get('hash_prevout_stake')) \
        + int_to_hex(int(header_dict.get('hash_prevout_n')), 4) \
        + var_int(sig_length) \
        + (header_dict.get('sig'))
    return s


class Deserializer(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    def __init__(self, binary, start=0):
        assert isinstance(binary, bytes)
        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def read_varbytes(self):
        return self._read_nbytes(self.read_varint())

    def read_varint(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert self.binary_length >= end
        return self.binary[cursor:end]

    def _read_le_int32(self):
        result, = unpack_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result


def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    if len(s) < BASIC_HEADER_SIZE:
        raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int.from_bytes(s, byteorder='little')
    deserializer = Deserializer(s, start=BASIC_HEADER_SIZE)
    sig_length = deserializer.read_varint()

    h = {
        'block_height': height,
        'version': hex_to_int(s[0:4]),
        'prev_block_hash': hash_encode(s[4:36]),
        'merkle_root': hash_encode(s[36:68]),
        'timestamp': hex_to_int(s[68:72]),
        'bits': hex_to_int(s[72:76]),
        'nonce': hex_to_int(s[76:80]),
        'hash_state_root': hash_encode(s[80:112]),
        'hash_utxo_root': hash_encode(s[112:144]),
        'hash_prevout_stake': hash_encode(s[144:176]),
        'hash_prevout_n': hex_to_int(s[176:180]),
        'sig': hash_encode(s[:-sig_length - 1:-1]),
    }
    return h


def hash_header(header: dict) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_header(header))


def hash_raw_header(header: str) -> str:
    return hash_encode(sha256d(bfh(header)))


# key: blockhash hex at forkpoint
# the chain at some key is the best chain that includes the given hash
blockchains = {}  # type: Dict[str, Blockchain]
blockchains_lock = threading.RLock()  # lock order: take this last; so after Blockchain.lock


def read_blockchains(config: 'SimpleConfig'):
    best_chain = Blockchain(config=config,
                            forkpoint=0,
                            parent=None,
                            forkpoint_hash=constants.net.GENESIS,
                            prev_hash=None)
    blockchains[constants.net.GENESIS] = best_chain

    # forks
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    util.make_dir(fdir)
    # files are named as: fork2_{forkpoint}_{prev_hash}_{first_hash}
    l = filter(lambda x: x.startswith('fork2_') and '.' not in x and len(x.split('_')) == 4, os.listdir(fdir))
    l = sorted(l, key=lambda x: int(x.split('_')[1]))  # sort by forkpoint

    def delete_chain(filename, reason):
        _logger.info(f"[blockchain] deleting chain {filename}: {reason}")
        path = os.path.join(fdir, filename)
        try:
            os.unlink(path)
        except BaseException as e:
            _logger.error(f"failed delete {path} {e}")

    def instantiate_chain(filename):
        __, forkpoint, prev_hash, first_hash = filename.split('_')
        forkpoint = int(forkpoint)
        prev_hash = (64-len(prev_hash)) * "0" + prev_hash  # left-pad with zeroes
        first_hash = (64-len(first_hash)) * "0" + first_hash
        # forks below the max checkpoint are not allowed
        if forkpoint <= constants.net.max_checkpoint():
            delete_chain(filename, "deleting fork below max checkpoint")
            return
        # find parent (sorting by forkpoint guarantees it's already instantiated)
        for parent in blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(config=config,
                       forkpoint=forkpoint,
                       parent=parent,
                       forkpoint_hash=first_hash,
                       prev_hash=prev_hash)
        # consistency checks
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h) or not b.parent.can_connect(h, check_height=False):
            if b.conn:
                b.conn.close()
            delete_chain(filename, "invalid fork")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        blockchains[chain_id] = b

    for filename in l:
        instantiate_chain(filename)


def get_best_chain() -> 'Blockchain':
    return blockchains[constants.net.GENESIS]

# block hash -> chain work; up to and including that block
_CHAINWORK_CACHE = {
    "0000000000000000000000000000000000000000000000000000000000000000": 0,  # virtual block at height -1
}  # type: Dict[str, int]


# def init_headers_file_for_best_chain():
#     b = get_best_chain()
#     filename = b.path()
#     length = HEADER_SIZE * len(constants.net.CHECKPOINTS) * 2016
#     if not os.path.exists(filename) or os.path.getsize(filename) < length:
#         with open(filename, 'wb') as f:
#             if length > 0:
#                 f.seek(length - 1)
#                 f.write(b'\x00')
#         util.ensure_sparse_file(filename)
#     with b.lock:
#         b.update_size()


class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config: SimpleConfig, forkpoint: int, parent: Optional['Blockchain'],
                 forkpoint_hash: str, prev_hash: Optional[str]):
        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint <= constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.config = config
        self.forkpoint = forkpoint  # height of first header
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
        self.swaping = threading.Event()
        self.conn = None
        self.init_db()
        self.update_size()

    def with_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def init_db(self):
        self.conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = self.conn.cursor()
        try:
            cursor.execute('CREATE TABLE IF NOT EXISTS header '
                           '(height INT PRIMARY KEY NOT NULL, data BLOB NOT NULL)')
            self.conn.commit()
        except (sqlite3.DatabaseError, ) as e:
            self.logger.info(f"error when init_db', {e}, 'will delete the db file and recreate")
            os.remove(self.path())
            self.conn = None
            self.init_db()
        finally:
            cursor.close()

    @with_lock
    def is_valid(self):
        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT min(height), max(height) FROM header')
        min_height, max_height = cursor.fetchone()
        max_height = max_height or 0
        min_height = min_height or 0
        cursor.execute('SELECT COUNT(*) FROM header')
        size = int(cursor.fetchone()[0])
        cursor.close()
        conn.close()
        if not min_height == self.forkpoint:
            return False
        if size > 0 and not size == max_height - min_height + 1:
            return False
        return True

    @property
    def checkpoints(self):
        return constants.net.CHECKPOINTS

    def get_max_child(self) -> Optional[int]:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        """Returns the max height where there is a fork
        related to this chain.
        """
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> Sequence['Blockchain']:
        with blockchains_lock:
            return list(filter(lambda y: y.parent==self, blockchains.values()))

    def get_parent_heights(self) -> Mapping['Blockchain', int]:
        """Returns map: (parent chain -> height of last common block)"""
        with self.lock, blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None: break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain: 'Blockchain') -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def get_name(self) -> str:
        return self.get_hash(self.get_max_forkpoint()).lstrip('0')[0:10]

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get('block_height')
        return self.check_hash(height, header_hash)

    def check_hash(self, height: int, header_hash: str) -> bool:
        """Returns whether the hash of the block at given height
        is the given hash.
        """
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash  # hex
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> 'Blockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = Blockchain(config=parent.config,
                          forkpoint=forkpoint,
                          parent=parent,
                          forkpoint_hash=hash_header(header),
                          prev_hash=parent.get_hash(forkpoint-1))
        self.logger.info(f'[fork] {forkpoint}, {parent.forkpoint}')
        self.assert_headers_file_available(parent.path())
        # open(self.path(), 'w+').close()
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with blockchains_lock:
            blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM header')
        count = int(cursor.fetchone()[0])
        self._size = count
        cursor.close()

    @classmethod
    def is_pos(cls, header: dict):
        hash_prevout_stake = header.get('hash_prevout_stake', None)
        hash_prevout_n = header.get('hash_prevout_n', 0)
        return hash_prevout_stake and (
                hash_prevout_stake != '0000000000000000000000000000000000000000000000000000000000000000'
                or hash_prevout_n != 0xffffffff)

    @classmethod
    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise Exception("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))

        if constants.net.TESTNET:
            return

        if cls.is_pos(header):
            # verifying pos header requires too much data to be implemented in light client
            pass
        else:
            block_hash_as_num = int.from_bytes(bfh(_hash), byteorder='big')
            if block_hash_as_num > target:
                raise Exception(f"insufficient proof of work: {block_hash_as_num} vs target {target}")

        bits = cls.target_to_bits(target)
        if bits != header.get('bits'):
            raise Exception(f"{header.get('block_height')} bits mismatch: {bits} vs {header.get('bits')}")

    def verify_chunk(self, index: int, raw_headers: list) -> None:
        prev_header = None
        pprev_header = None
        if index != 0:
            prev_header = self.read_header(index * CHUNK_SIZE - 1)
            pprev_header = self.read_header(index * CHUNK_SIZE - 2)
        for i, raw_header in enumerate(raw_headers):
            height = index * CHUNK_SIZE + i
            header = deserialize_header(raw_header, height)
            target = self.get_target(height, is_pos=self.is_pos(header), prev_header=prev_header, pprev_header=pprev_header)
            self.verify_header(header, hash_header(prev_header), target)
            pprev_header = prev_header
            prev_header = header

    @with_lock
    def path(self):
        d = util.get_headers_dir(self.config)
        if self.parent is None:
            filename = 'blockchain_headers'
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip('0')
            first_hash = self._forkpoint_hash.lstrip('0')
            basename = f'fork2_{self.forkpoint}_{prev_hash}_{first_hash}'
            filename = os.path.join('forks', basename)
        return os.path.join(d, filename)

    @with_lock
    def save_chunk(self, index: int, raw_headers: list):
        self.logger.info(f'{self.forkpoint} try to save chunk {(index * CHUNK_SIZE)}')
        assert index >= 0, index

        if self.swaping.is_set():
            return
        try:
            conn = self.conn
            cursor = self.conn.cursor()
        except (sqlite3.ProgrammingError, AttributeError):
            conn = sqlite3.connect(self.path(), check_same_thread=False)
            cursor = conn.cursor()

        forkpoint = self.forkpoint
        if forkpoint is None:
            forkpoint = 0
        headers = [(index * CHUNK_SIZE + i, v)
                   for i, v in enumerate(raw_headers)
                   if index * CHUNK_SIZE + i >= forkpoint]

        cursor.executemany('REPLACE INTO header (height, data) VALUES(?,?)', headers)
        cursor.close()
        conn.commit()
        self.update_size()
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        if self.parent is None:
            return
        with self.lock, blockchains_lock:
            parent = self.parent

            self.update_size()
            parent.update_size()
            parent_branch_size = parent.height() - self.forkpoint + 1
            if parent_branch_size >= self._size:
                return

            if self.swaping.is_set() or parent.swaping.is_set():
                return
            self.swaping.set()
            parent.swaping.set()

            parent_id = parent.get_id()
            forkpoint = self.forkpoint

            global blockchains
            try:
                self.logger.info(f'swap, {forkpoint}, {parent_id}')
                for i in range(forkpoint, forkpoint + self._size):
                    # print_error('swaping', i)
                    header = self.read_header(i, deserialize=False)
                    parent_header = parent.read_header(i, deserialize=False)
                    parent.write(header, i)
                    if parent_header:
                        self.write(parent_header, i)
                    else:
                        self.delete(i)
            except (BaseException,) as e:
                import traceback, sys
                traceback.print_exc(file=sys.stderr)
                self.logger.error(f'swap error, {e}')
            # update size
            self.update_size()
            parent.update_size()
            self.swaping.clear()
            parent.swaping.clear()
            self.logger.info('swap finished')
            parent.swap_with_parent()

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    def write(self, raw_header: bytes, height: int):
        if self.forkpoint > 0 and height < self.forkpoint:
            return
        if not raw_header:
            if height:
                self.delete(height)
            else:
                self.delete_all()
            return
        with self.lock:
            self.logger.info(f'{self.path()} {self.forkpoint} try to write {height}')
            if height > self._size + self.forkpoint:
                return
            try:
                conn = self.conn
                cursor = self.conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('REPLACE INTO header (height, data) VALUES(?,?)', (height, raw_header))
            cursor.close()
            conn.commit()
            self.update_size()

    def delete(self, height: int):
        self.logger.info(f'{self.forkpoint} try to delete {height}')
        if self.forkpoint > 0 and height < self.forkpoint:
            return
        with self.lock:
            self.logger.info(f'{self.forkpoint} try to delete {height}')
            try:
                conn = self.conn
                cursor = conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('DELETE FROM header where height=?', (height,))
            cursor.close()
            conn.commit()
            self.update_size()

    def delete_all(self):
        if self.swaping.is_set():
            return
        with self.lock:
            try:
                conn = self.conn
                cursor = self.conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('DELETE FROM header')
            cursor.close()
            conn.commit()
            self._size = 0

    @with_lock
    def save_header(self, header: dict) -> None:
        data = bfh(serialize_header(header))
        self.write(data, header.get('block_height'))
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int, deserialize=True) -> Union[dict, bytes]:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return

        try:
            conn = sqlite3.connect(self.path(), check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('SELECT data FROM header WHERE height=?', (height,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
        except BaseException as e:
            self.logger.error(f'read_header error:{e}')
            return

        if not result or len(result) < 1:
            self.logger.error(f'read_header {height}, {self.forkpoint}, {self.parent.get_id()}, {result}, {self.height()}')
            self.update_size()
            return
        header = result[0]
        if deserialize:
            return deserialize_header(header, height)
        return header

    def header_at_tip(self) -> Optional[dict]:
        """Return latest header."""
        height = self.height()
        return self.read_header(height)

    def is_tip_stale(self) -> bool:
        STALE_DELAY = 8 * 60 * 60  # in seconds
        header = self.header_at_tip()
        if not header:
            return True
        # note: We check the timestamp only in the latest header.
        #       The Bitcoin consensus has a lot of leeway here:
        #       - needs to be greater than the median of the timestamps of the past 11 blocks, and
        #       - up to at most 2 hours into the future compared to local clock
        #       so there is ~2 hours of leeway in either direction
        if header['timestamp'] + STALE_DELAY < time.time():
            return True
        return False

    def get_hash(self, height: int) -> str:
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif str(height) in self.checkpoints:
            return self.checkpoints[str(height)]
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    @classmethod
    def get_limit(cls, height: int, net, is_pos: bool):
        if is_pos:
            if height < net.QIP9_FORK_HEIGHT:
                return net.POS_LIMIT
            elif height < net.REDUCE_BLOCK_TIME_HEIGHT:
                return net.QIP9_POS_LIMIT
            return net.RBT_POS_LIMIT
        return net.POW_LIMIT

    def get_target(self, height: int, is_pos: bool, prev_header=None, pprev_header=None) -> int:
        """
        https://github.com/qtumproject/qtum/blob/master/src/pow.cpp CalculateNextWorkRequired
        """
        net = constants.net

        # only for mainnet
        if height <= POW_BLOCK_COUNT:
            return net.POW_LIMIT
        if height <= POW_BLOCK_COUNT + 2:
            return net.POS_LIMIT

        if not prev_header:
            prev_header = self.read_header(height - 1)
        if not pprev_header:
            pprev_header = self.read_header(height - 2)

        if not prev_header:
            raise Exception('get header failed {}'.format(height - 1))
        if not pprev_header:
            raise Exception('get header failed {}'.format(height - 2))

        new_target = self.bits_to_target(prev_header.get('bits'))

        if is_pos:
            if net.POS_NO_RETARGET:
                return new_target
        else:
            # no retarget for pow
            return new_target

        #  Limit adjustment step
        nActualSpace = prev_header.get('timestamp') - pprev_header.get('timestamp')
        nActualSpace = max(0, nActualSpace)

        #  Retarget
        if height < net.QIP9_FORK_HEIGHT:
            nActualSpace = min(nActualSpace, POW_TARGET_TIMESPACE * 10)
            nInterval = POW_TARGET_TIMESPAN // POW_TARGET_TIMESPACE
            new_target *= ((nInterval - 1) * POW_TARGET_TIMESPACE + nActualSpace + nActualSpace)
            new_target //= ((nInterval + 1) * POW_TARGET_TIMESPACE)
        elif height < net.REDUCE_BLOCK_TIME_HEIGHT:
            nActualSpace = min(nActualSpace, POW_TARGET_TIMESPACE * 20)
            nInterval = POW_TARGET_TIMESPAN_V2 // POW_TARGET_TIMESPACE
            t1 = int(2 * (nActualSpace - POW_TARGET_TIMESPACE) / 16)
            t2 = (nInterval + 1) * POW_TARGET_TIMESPACE // 16
            new_target *= math.exp(t1 / t2)
            new_target = int(new_target)
        else:
            nActualSpace = min(nActualSpace, POW_TARGET_TIMESPACE_RBT * 20)
            nInterval = POW_TARGET_TIMESPAN_RBT // POW_TARGET_TIMESPACE_RBT
            t1 = int(2 * (nActualSpace - POW_TARGET_TIMESPACE_RBT) / 4)
            t2 = (nInterval + 1) * POW_TARGET_TIMESPACE_RBT // 4
            new_target *= math.exp(t1 / t2)
            new_target = int(new_target)

        target_limit = self.get_limit(height, net, is_pos)
        if new_target <= 0 or new_target > target_limit:
            new_target = target_limit

        new_target = self.bits_to_target(self.target_to_bits(new_target))
        return new_target

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        mainnet = not constants.net.TESTNET
        bitsN = (bits >> 24) & 0xff
        if mainnet and not (0x03 <= bitsN <= 0x1d):
            raise Exception("First part of bits should be in [0x03, 0x1d]")
        bitsBase = bits & 0xffffff
        if mainnet and not (0x8000 <= bitsBase <= 0x7fffff):
            raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int.from_bytes(bfh(c[:6]), byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    @with_lock
    def get_chainwork(self, height=None) -> int:
        if height is None:
            height = max(0, self.height())
        return height

    def can_connect(self, header: dict, check_height: bool=True) -> bool:
        if not header:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            self.logger.info(f'[can_connect] check_height failed {height}, {self.height()}')
            return False
        if height == 0:
            valid = hash_header(header) == constants.net.GENESIS
            if not valid:
                self.logger.info(f'[can_connect] GENESIS hash check {hash_header(header)}, {constants.net.GENESIS}')
            return valid
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            self.logger.info(f'[can_connect] cannot ger prev_hash {height}')
            return False
        if prev_hash != header.get('prev_block_hash'):
            self.logger.info(f'[can_connect] prev hash check failed {height}')
            return False
        target = self.get_target(height, is_pos=self.is_pos(header))
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException as e:
            self.logger.info(f'[can_connect] verify_header failed {e} {height}')
            return False
        return True

    @classmethod
    def read_chunk(cls, data):
        def read_a_raw_header_from_chunk(data, start):
            deserializer = Deserializer(data, start=start + BASIC_HEADER_SIZE)
            sig_length = deserializer.read_varint()
            cursor = deserializer.cursor + sig_length
            return data[start: cursor], cursor

        raw_headers = []
        cursor = 0
        while cursor < len(data):
            raw_header, cursor = read_a_raw_header_from_chunk(data, cursor)
            if not raw_header:
                raise Exception('read_chunk, no header read')
            raw_headers.append(raw_header)
        return raw_headers

    def connect_chunk(self, idx: int, hexdata: str) -> bool:
        assert idx >= 0, idx
        try:
            data = bfh(hexdata)
            raw_heades = self.read_chunk(data)
            self.verify_chunk(idx, raw_heades)
            self.save_chunk(idx, raw_heades)
            return True
        except BaseException as e:
            self.logger.info(f'verify_chunk idx {idx} failed: {repr(e)}')
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = {}
        n = self.height() // CHUNK_SIZE
        for index in range(n):
            height = (index+1) * CHUNK_SIZE - 1
            blockhash = self.get_hash(height)
            cp[height] = blockhash
        return cp


def check_header(header: dict) -> Optional[Blockchain]:
    """Returns any Blockchain that contains header, or None."""
    if type(header) is not dict:
        return None
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.check_header(header):
            return b
    return None


def can_connect(header: dict) -> Optional[Blockchain]:
    """Returns the Blockchain that has a tip that directly links up
    with header, or None.
    """
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.can_connect(header):
            return b
    return None


def get_chains_that_contain_header(height: int, header_hash: str) -> Sequence[Blockchain]:
    """Returns a list of Blockchains that contain header, best chain first."""
    with blockchains_lock: chains = list(blockchains.values())
    chains = [chain for chain in chains
              if chain.check_hash(height=height, header_hash=header_hash)]
    chains = sorted(chains, key=lambda x: x.get_chainwork(), reverse=True)
    return chains
