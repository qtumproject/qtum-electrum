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
import threading
import sqlite3
from . import util
from . import qtum
from . import constants
from .qtum import *


blockchains = {}


def read_blockchains(config):
    global blockchains
    main_chain = Blockchain(config, 0, None)
    blockchains[0] = main_chain

    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    util.make_dir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    bad_chains = []
    main_chain_height = main_chain.height()
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        if not b.is_valid():
            bad_chains.append(b.checkpoint)
        if b.parent_id == 0 and b.height() < main_chain_height - 100:
            bad_chains.append(b.checkpoint)
        blockchains[b.checkpoint] = b
    if not main_chain.is_valid():
        bad_chains.append(0)

    for bad_k in bad_chains:
        remove_chain(bad_k, blockchains)
    if len(blockchains) == 0:
        blockchains[0] = Blockchain(config, 0, None)
    return blockchains


def remove_chain(cp, chains):
    try:
        os.remove(chains[cp].path())
        del chains[cp]
        print_error('chain removed', cp)
    except (BaseException,) as e:
        print_error('remove_chain error', e)
    for k in list(chains.keys()):
        if chains[k].parent_id == cp:
            remove_chain(chains[k].checkpoint, chains)


def check_header(header):
    if type(header) is not dict:
        print_error('[check_header] header not dic')
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False


def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.checkpoints = constants.net.CHECKPOINTS
        self.parent_id = parent_id
        self.lock = threading.Lock()
        self.swaping = threading.Event()
        self.conn = None
        self.init_db()
        with self.lock:
            self.update_size()

    def init_db(self):
        self.conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = self.conn.cursor()
        try:
            cursor.execute('CREATE TABLE IF NOT EXISTS header '
                           '(height INT PRIMARY KEY NOT NULL, data BLOB NOT NULL)')
            self.conn.commit()
        except (sqlite3.DatabaseError, ) as e:
            print_error('error when init_db', e, 'will delete the db file and recreate')
            os.remove(self.path())
            self.conn = None
            self.init_db()
        finally:
            cursor.close()

    def is_valid(self):
        with self.lock:
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
            if not min_height == self.checkpoint:
                return False
            if size > 0 and not size == max_height - min_height + 1:
                return False
        return True

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None \
            else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        print_error('[fork]', checkpoint, parent.checkpoint)
        self.save_header(header)
        return self

    def _height(self):
        return self.checkpoint + self._size - 1

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM header')
        count = int(cursor.fetchone()[0])
        self._size = count
        cursor.close()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        self.update_size()
        parent.update_size()
        parent_branch_size = parent._height() - self.checkpoint + 1
        if parent_branch_size >= self._size:
            return
        if self.swaping.is_set() or parent.swaping.is_set():
            return
        self.swaping.set()
        parent.swaping.set()
        global blockchains
        try:
            print_error('swap', self.checkpoint, self.parent_id)
            for i in range(checkpoint, checkpoint + self._size):
                print_error('swaping', i)
                header = self.read_header(i, deserialize=False)
                parent_header = parent.read_header(i, deserialize=False)
                parent._write(header, i)
                if parent_header:
                    self._write(parent_header, i)
                else:
                    self._delete(i)
        except (BaseException,) as e:
            self.print_error('swap error', e)
        # update size
        self.update_size()
        parent.update_size()
        self.swaping.clear()
        parent.swaping.clear()
        print_error('swap finished')
        parent.swap_with_parent()

    def _write(self, raw_header, height):
        self.print_error('{} try to write {}'.format(self.checkpoint, height))
        if height > self._size + self.checkpoint:
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

    def write(self, raw_header, height):
        if self.swaping.is_set():
            return
        if self.checkpoint > 0 and height < self.checkpoint:
            return
        if not raw_header:
            if height:
                self.delete(height)
            else:
                self.delete_all()
            return
        with self.lock:
            self.update_size()
            self._write(raw_header, height)
            self.update_size()

    def _delete(self, height):
        self.print_error('{} try to delete {}'.format(self.checkpoint, height))
        try:
            conn = self.conn
            cursor = conn.cursor()
        except (sqlite3.ProgrammingError, AttributeError):
            conn = sqlite3.connect(self.path(), check_same_thread=False)
            cursor = conn.cursor()
        cursor.execute('DELETE FROM header where height=?', (height,))
        cursor.close()
        conn.commit()

    def delete(self, height):
        if self.swaping.is_set():
            return
        self.print_error('{} try to delete {}'.format(self.checkpoint, height))
        if self.checkpoint > 0 and height < self.checkpoint:
            return
        with self.lock:
            self._delete(height)
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

    def save_header(self, header):
        data = bfh(serialize_header(header))
        self.write(data, header.get('block_height'))
        self.swap_with_parent()

    def read_header(self, height, deserialize=True):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height > self._height():
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)

        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT data FROM header WHERE height=?', (height,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if not result or len(result) < 1:
            print_error('read_header 4', height, self.checkpoint, self.parent_id, result, self._height())
            self.update_size()
            return
        header = result[0]
        if deserialize:
            return deserialize_header(header, height)
        return header

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = hash_header(prev_header)
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return True

        if bits != header.get('bits'):
            raise Exception("bits mismatch: %s vs %s, %s" %
                                (hex(bits), hex(header.get('bits')), _hash))

        if is_pos(header):
            pass
            # todo
            # 需要拿到value，计算新的target
        else:
            if int('0x' + _hash, 16) > target:
                raise Exception("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        real_hash = self.get_hash(height)
        return header_hash == real_hash

    def save_chunk(self, index, raw_headers):
        print_error('{} try to save chunk {}'.format(self.checkpoint, index * CHUNK_SIZE))
        if self.swaping.is_set():
            return
        with self.lock:
            try:
                conn = self.conn
                cursor = self.conn.cursor()
            except (sqlite3.ProgrammingError, AttributeError):
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            headers = list([(index * CHUNK_SIZE + i, v) for i, v in enumerate(raw_headers)])
            cursor.executemany('REPLACE INTO header (height, data) VALUES(?,?)', headers)
            cursor.close()
            conn.commit()
            self.update_size()
        self.swap_with_parent()

    def read_chunk(self, data):
        raw_headers = []
        cursor = 0
        while cursor < len(data):
            raw_header, cursor = read_a_raw_header_from_chunk(data, cursor)
            if not raw_header:
                raise Exception('read_chunk, no header read')
            raw_headers.append(raw_header)
        return raw_headers

    def verify_chunk(self, index, raw_headers):
        prev_header = None
        pprev_header = None
        if index != 0:
            prev_header = self.read_header(index * CHUNK_SIZE - 1)
            pprev_header = self.read_header(index * CHUNK_SIZE - 2)
        for i, raw_header in enumerate(raw_headers):
            height = index * CHUNK_SIZE + i
            header = deserialize_header(raw_header, height)
            bits, target = self.get_target(height, prev_header=prev_header, pprev_header=pprev_header)
            self.verify_header(header, prev_header, bits, target)
            pprev_header = prev_header
            prev_header = header

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        if str(height) in self.checkpoints:
            return self.checkpoints[str(height)]
        return hash_header(self.read_header(height))

    def BIP9(self, height, flag):
        v = self.read_header(height)['version']
        return ((v & 0xE0000000) == 0x20000000) and ((v & flag) == flag)

    def segwit_support(self, N=144):
        h = self.local_height
        return sum([self.BIP9(h-i, 2) for i in range(N)])*10000/N/100.

    def get_target(self, height, prev_header=None, pprev_header=None):
        if height <= POW_BLOCK_COUNT:
            return compact_from_uint256(POW_LIMIT), POW_LIMIT
        if height <= POW_BLOCK_COUNT + 2:
            return compact_from_uint256(POS_LIMIT), POS_LIMIT

        if not prev_header:
            prev_header = self.read_header(height - 1)
        if not pprev_header:
            pprev_header = self.read_header(height - 2)

        if not prev_header:
            raise Exception('get header failed {}'.format(height - 1))
        if not pprev_header:
            raise Exception('get header failed {}'.format(height - 2))

        #  Limit adjustment step
        nActualSpace = prev_header.get('timestamp') - pprev_header.get('timestamp')
        nActualSpace = max(0, nActualSpace)
        nActualSpace = min(nActualSpace, POW_TARGET_TIMESPACE * 10)
        #  Retarget
        nInterval = POW_TARGET_TIMESPAN // POW_TARGET_TIMESPACE
        new_target = uint256_from_compact(prev_header.get('bits'))
        new_target *= ((nInterval - 1) * POW_TARGET_TIMESPACE + nActualSpace + nActualSpace)
        new_target //= ((nInterval + 1) * POW_TARGET_TIMESPACE)

        if new_target <= 0 or new_target > POS_LIMIT:
            new_target = POS_LIMIT

        nbits = compact_from_uint256(new_target)
        new_target = uint256_from_compact(nbits)

        return nbits, new_target

    def can_connect(self, header, check_height=True):
        if not header:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            print_error('[can_connect] check_height failed', height, self.height())
            return False
        if height == 0:
            valid = hash_header(header) == constants.net.GENESIS
            if not valid:
                print_error('[can_connect] GENESIS hash check', hash_header(header), constants.net.GENESIS)
            return valid
        prev_header = self.read_header(height - 1)
        if not prev_header:
            print_error('[can_connect] no prev_header', height)
            return False
        prev_hash = hash_header(prev_header)
        if prev_hash != header.get('prev_block_hash'):
            print_error('[can_connect] hash check failed', height)
            return False
        bits, target = self.get_target(height)
        try:
            self.verify_header(header, prev_header, bits, target)
        except BaseException as e:
            print_error('[can_connect] verify_header failed', e, height)
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            raw_heades = self.read_chunk(data)
            self.verify_chunk(idx, raw_heades)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, raw_heades)
            return True
        except BaseException as e:
            self.print_error('connect_chunk failed', str(e))
            return False
