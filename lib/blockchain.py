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
import threading
import sqlite3
from . import util
from . import qtum
from .qtum import *


def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))


blockchains = {}


def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    bad_chains = []
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        if not b.is_valid():
            bad_chains.append(b.checkpoint)
        blockchains[b.checkpoint] = b

    def remove_chain(cp, chains):
        try:
            chains[cp].close()
            os.remove(chains[cp].path())
            del chains[cp]
        except (BaseException,) as e:
            pass
        for k in list(chains.keys()):
            if chains[k].parent_id == cp:
                remove_chain(b.checkpoint, chains)

    for bad_k in bad_chains:
        remove_chain(bad_k, blockchains)
    if len(blockchains) == 0:
        blockchains[0] = Blockchain(config, 0, None)
    return blockchains


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
        self.parent_id = parent_id
        self.lock = threading.Lock()
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
            cursor = self.conn.cursor()
            cursor.execute('SELECT min(height), max(height) FROM header')
            min_height, max_height = cursor.fetchone()
            cursor.execute('SELECT COUNT(*) FROM header')
            size = int(cursor.fetchone()[0])
            cursor.close()
            if not min_height == self.checkpoint:
                return False
            if not size == max_height - min_height + 1:
                return False
        return True

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None \
            else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def close(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()
        self.print_error('stopped')

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

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        real_hash = self.get_hash(height)
        return header_hash == real_hash

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        print_error('[fork]', checkpoint, parent.checkpoint)
        self.save_header(header)
        return self

    def height(self):
        height = self.checkpoint + self.size() - 1
        # print_error('[blockchain height]', height, self.checkpoint, self.size())
        return height

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM header')
        count = int(cursor.fetchone()[0])
        cursor.close()
        conn.close()
        self._size = count

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = hash_header(prev_header)
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if qtum.TESTNET:
            return True

        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s, %s" %
                                (hex(bits), hex(header.get('bits')), _hash))

        if is_pos(header):
            pass
            # todo
            # 需要拿到value，计算新的target
        else:
            if int('0x' + _hash, 16) > target:
                raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

    def read_chunk(self, data):
        raw_headers = []
        cursor = 0
        while cursor < len(data):
            raw_header, cursor = read_a_raw_header_from_chunk(data, cursor)
            if not raw_header:
                raise BaseException('read_chunk, no header read')
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

    def save_chunk(self, index, raw_headers):
        for i, raw_header in enumerate(raw_headers):
            height = index * CHUNK_SIZE + i
            self.write(raw_header, height)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        self.update_size()
        self.parent().update_size()
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        print('swap', self.checkpoint, self.parent_id)
        for i in range(checkpoint, checkpoint + self.size()):
            header = self.read_header(i, deserialize=False)
            parent_header = parent.read_header(i, deserialize=False)
            parent.write(header, i)
            if parent_header:
                self.write(parent_header, i)
            else:
                self.delete(i)

        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id
        parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint
        parent.checkpoint = checkpoint
        self.update_size()
        parent.update_size()

        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def write(self, raw_header, height):
        self.print_error('{} try to write {}'.format(self.checkpoint, height))
        if self.checkpoint > 0 and height < self.checkpoint:
            return
        if not raw_header:
            if height:
                self.delete(height)
            else:
                self.delete_all()
            return

        with self.lock:
            try:
                cursor = self.conn.cursor()
            except sqlite3.ProgrammingError:
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('REPLACE INTO header (height, data) VALUES(?,?)', (height, raw_header))
            cursor.close()
            self.conn.commit()
            self.update_size()

    def delete(self, height):
        self.print_error('{} try to delete {}'.format(self.checkpoint, height))
        if self.checkpoint > 0 and height < self.checkpoint:
            return
        with self.lock:
            try:
                cursor = self.conn.cursor()
            except sqlite3.ProgrammingError:
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('DELETE FROM header where height=?', (height,))
            cursor.close()
            self.conn.commit()
            self.update_size()

    def delete_all(self):
        with self.lock:
            try:
                cursor = self.conn.cursor()
            except sqlite3.ProgrammingError:
                conn = sqlite3.connect(self.path(), check_same_thread=False)
                cursor = conn.cursor()
            cursor.execute('DELETE FROM header')
            cursor.close()
            self.conn.commit()
            self._size = 0

    def save_header(self, header):
        data = bfh(serialize_header(header))
        self.write(data, header.get('block_height'))
        self.swap_with_parent()

    def read_header(self, height, deserialize=True):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height > self.height():
            # print_error('read_header 3', height, self.checkpoint, self.parent_id)
            return
        if height < self.checkpoint:
            # header = self.parent().read_header(height)
            conn = sqlite3.connect(self.parent().path(), check_same_thread=False)
            # print_error('read_header 2', height, self.checkpoint, self.parent_id, result)
        else:
            conn = sqlite3.connect(self.path(), check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT data FROM header WHERE height=?', (height,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if not result or len(result) < 1:
            print_error('read_header 4', height, self.checkpoint, self.parent_id, result, self.height())
            return
        header = result[0]
        if deserialize:
            return deserialize_header(header, height)
        return header

    def get_hash(self, height):
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
            raise BaseException('get header failed {}'.format(height - 1))
        if not pprev_header:
            raise BaseException('get header failed {}'.format(height - 2))

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

    #  # bitcoin
    # def get_target(self, index):
    #     if bitcoin.TESTNET:
    #         return 0, 0
    #     if index == 0:
    #         return GENESIS_BITS, MAX_TARGET
    #
    #     first = self.read_header((index-1) * 2016)
    #     last = self.read_header(index*2016 - 1)
    #     # bits to target
    #     bits = last.get('bits')
    #
    #     bitsN = (bits >> 24) & 0xff
    #
    #     if not (bitsN >= 0x03 and bitsN <= 0x1d):
    #         raise BaseException("First part of bits should be in [0x03, 0x1d]")
    #
    #     bitsBase = bits & 0xffffff
    #     if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
    #         raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
    #     target = bitsBase << (8 * (bitsN-3))
    #     # new target
    #     nActualTimespan = last.get('timestamp') - first.get('timestamp')
    #     nTargetTimespan = 14 * 24 * 60 * 60
    #     nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
    #     nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
    #     new_target = min(MAX_TARGET, (target * nActualTimespan) // nTargetTimespan)
    #     # convert new target to bits
    #     c = ("%064x" % new_target)[2:]
    #     while c[:2] == '00' and len(c) > 6:
    #         c = c[2:]
    #     bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
    #     if bitsBase >= 0x800000:
    #         bitsN += 1
    #         bitsBase >>= 8
    #     new_bits = bitsN << 24 | bitsBase
    #     return new_bits, bitsBase << (8 * (bitsN - 3))

    def can_connect(self, header, check_height=True):
        height = header['block_height']
        if check_height and self.height() != height - 1:
            print_error('[can_connect] check_height failed', height)
            return False
        if height == 0:
            valid = hash_header(header) == qtum.GENESIS
            if not valid:
                print_error('[can_connect] GENESIS hash check', hash_header(header), qtum.GENESIS)
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
