# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import hashlib
import hmac
from typing import List, Tuple
from enum import IntEnum
from eth_abi import encode_abi
from eth_utils import function_abi_to_4byte_selector

from .util import bfh, bh2u, assert_bytes, to_bytes, inv_dict, QtumException
from .util import unpack_uint16_from, unpack_uint32_from, unpack_uint64_from, unpack_int32_from, unpack_int64_from
from . import version
from . import constants
from . import segwit_addr
from . import ecc
from .crypto import sha256d, sha256, hash_160

TOKEN_TRANSFER_TOPIC = 'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'

BASIC_HEADER_SIZE = 180  # not include sig
POW_BLOCK_COUNT = 5000
CHUNK_SIZE = 1024
POW_LIMIT = 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
POS_LIMIT = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
POW_TARGET_TIMESPAN = 16 * 60  # bitcoin is 14 * 24 * 60 * 60
POW_TARGET_TIMESPACE = 2 * 64  # bitcoin is 10 * 60
RECOMMEND_CONFIRMATIONS = 10

mainnet_block_explorers = {
    'qtum.info': ('https://qtum.info',
                  {'tx': 'tx', 'addr': 'address', 'contract': 'contract'}),
    'explorer.qtum.org': ('https://explorer.qtum.org',
                          {'tx': 'tx', 'addr': 'address', 'contract': 'contract'}),
    'qtumexplorer.io': ('https://qtumexplorer.io/',
                        {'tx': 'tx', 'addr': 'address', 'contract': 'contract'}),
}

testnet_block_explorers = {
    'qtum.info': ('https://testnet.qtum.info',
                  {'tx': 'tx', 'addr': 'address', 'contract': 'contract'}),
    'explorer.qtum.org': ('https://testnet.qtum.org/',
                          {'tx': 'tx', 'addr': 'address', 'contract': 'contract'}),
}


################################## transactions

FEERATE_MAX_DYNAMIC = 125000000
FEERATE_WARNING_HIGH_FEE = 1500000
FEERATE_FALLBACK_STATIC_FEE = 1000000
FEERATE_DEFAULT_RELAY = 400000
FEERATE_STATIC_VALUES = [410000, 500000, 600000, 700000, 800000, 1000000, 1300000, 1800000, 2000000, 2500000, 3000000]

FEE_TARGETS = [25, 10, 5, 2]

COINBASE_MATURITY = 500
COIN = 100000000
TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 100664516

# supported types of transction outputs
TYPE_ADDRESS = 0
TYPE_PUBKEY  = 1
TYPE_SCRIPT  = 2
TYPE_STAKE = 3


class opcodes(IntEnum):
    # push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99

    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4

    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    OP_INVALIDOPCODE = 0xff

    # qtum contract
    OP_CREATE = 0xC1
    OP_CALL = 0xC2
    OP_SPEND = 0xC3

    def hex(self) -> str:
        return bytes([self]).hex()


def rev_hex(s):
    return bh2u(bfh(s)[::-1])


def int_to_hex(i: int, length: int=1) -> str:
    assert isinstance(i, int)
    range_size = pow(256, length)
    if i < -(range_size // 2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)


def script_num_to_hex(i: int) -> str:
    """See CScriptNum in Bitcoin Core.
    Encodes an integer as hex, to be used in script.

    ported from https://github.com/bitcoin/bitcoin/blob/8cbc5c4be4be22aca228074f087a374a7ec38be8/src/script/script.h#L326
    """
    if i == 0:
        return ''

    result = bytearray()
    neg = i < 0
    absvalue = abs(i)
    while absvalue > 0:
        result.append(absvalue & 0xff)
        absvalue >>= 8

    if result[-1] & 0x80:
        result.append(0x80 if neg else 0x00)
    elif neg:
        result[-1] |= 0x80

    return bh2u(result)


def var_int(i: int) -> str:
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i<0xfd:
        return int_to_hex(i)
    elif i<=0xffff:
        return "fd"+int_to_hex(i,2)
    elif i<=0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)


def witness_push(item: str) -> str:
    """Returns data in the form it should be present in the witness.
    hex -> hex
    """
    return var_int(len(item) // 2) + item


def _op_push(i: int) -> str:
    if i < opcodes.OP_PUSHDATA1:
        return int_to_hex(i)
    elif i <= 0xff:
        return opcodes.OP_PUSHDATA1.hex() + int_to_hex(i, 1)
    elif i <= 0xffff:
        return opcodes.OP_PUSHDATA2.hex() + int_to_hex(i, 2)
    else:
        return opcodes.OP_PUSHDATA4.hex() + int_to_hex(i, 4)

def push_script(data: str) -> str:
    """Returns pushed data to the script, automatically
    choosing canonical opcodes depending on the length of the data.
    hex -> hex

    ported from https://github.com/btcsuite/btcd/blob/fdc2bc867bda6b351191b5872d2da8270df00d13/txscript/scriptbuilder.go#L128
    """
    data = bfh(data)
    data_len = len(data)

    # "small integer" opcodes
    if data_len == 0 or data_len == 1 and data[0] == 0:
        return opcodes.OP_0.hex()
    elif data_len == 1 and data[0] <= 16:
        return bh2u(bytes([opcodes.OP_1 - 1 + data[0]]))
    elif data_len == 1 and data[0] == 0x81:
        return opcodes.OP_1NEGATE.hex()

    return _op_push(data_len) + bh2u(data)


def add_number_to_script(i: int) -> bytes:
    return bfh(push_script(script_num_to_hex(i)))


hash_encode = lambda x: bh2u(x[::-1])
hash_decode = lambda x: bfh(x)[::-1]
hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).digest()


############ functions from pywallet #####################


def hash160_to_b58_address(h160: bytes, addrtype, witness_program_version=1):
    s = bytes([addrtype])
    s += h160
    return base_encode(s+sha256d(s)[0:4], base=58)


def b58_address_to_hash160(addr):
    addr = to_bytes(addr, 'ascii')
    _bytes = base_decode(addr, 25, base=58)
    return _bytes[0], _bytes[1:21]


def hash160_to_p2pkh(h160):
    return hash160_to_b58_address(h160, constants.net.ADDRTYPE_P2PKH)


def hash160_to_p2sh(h160):
    return hash160_to_b58_address(h160, constants.net.ADDRTYPE_P2SH)


def public_key_to_p2pkh(public_key: bytes) -> str:
    return hash160_to_p2pkh(hash_160(public_key))


def hash160_to_segwit_addr(h160):
    return segwit_addr.encode(constants.net.SEGWIT_HRP, 0, h160)


def hash_to_segwit_addr(h, witver):
    return segwit_addr.encode(constants.net.SEGWIT_HRP, witver, h)


def public_key_to_p2wpkh(public_key):
    return hash_to_segwit_addr(hash_160(public_key), witver=0)


def script_to_p2wsh(script):
    return hash_to_segwit_addr(sha256(bfh(script)), witver=0)


def p2wpkh_nested_script(pubkey):
    pkh = bh2u(hash_160(bfh(pubkey)))
    return '00' + push_script(pkh)


def p2wsh_nested_script(witness_script):
    wsh = bh2u(sha256(bfh(witness_script)))
    return '00' + push_script(wsh)


def pubkey_to_address(txin_type, pubkey):
    if txin_type == 'p2pkh':
        return public_key_to_p2pkh(bfh(pubkey))
    elif txin_type == 'p2wpkh':
        return public_key_to_p2wpkh(bfh(pubkey))
    elif txin_type == 'p2wpkh-p2sh':
        scriptSig = p2wpkh_nested_script(pubkey)
        return hash160_to_p2sh(hash_160(bfh(scriptSig)))
    else:
        raise NotImplementedError(txin_type)


def redeem_script_to_address(txin_type, redeem_script):
    if txin_type == 'p2sh':
        return hash160_to_p2sh(hash_160(bfh(redeem_script)))
    elif txin_type == 'p2wsh':
        return script_to_p2wsh(redeem_script)
    elif txin_type == 'p2wsh-p2sh':
        scriptSig = p2wsh_nested_script(redeem_script)
        return hash160_to_p2sh(hash_160(bfh(scriptSig)))
    else:
        raise NotImplementedError(txin_type)


def script_to_address(script, *, net=None):
    from .transaction import get_address_from_output_script
    t, addr = get_address_from_output_script(bfh(script), net=net)
    assert t == TYPE_ADDRESS
    return addr


def address_to_script(addr: str, *, net=None) -> str:
    if net is None: net = constants.net
    if not is_address(addr, net=net):
        raise QtumException(f"invalid bitcoin address: {addr}")
    witver, witprog = segwit_addr.decode(net.SEGWIT_HRP, addr)
    if witprog is not None:
        if not (0 <= witver <= 16):
            raise QtumException(f'impossible witness version: {witver}')
        script = bh2u(add_number_to_script(witver))
        script += push_script(bh2u(bytes(witprog)))
        return script
    addrtype, hash_160_ = b58_address_to_hash160(addr)
    if addrtype == net.ADDRTYPE_P2PKH:
        script = bytes([opcodes.OP_DUP, opcodes.OP_HASH160]).hex()
        script += push_script(bh2u(hash_160_))
        script += bytes([opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]).hex()
    elif addrtype == net.ADDRTYPE_P2SH:
        script = opcodes.OP_HASH160.hex()
        script += push_script(bh2u(hash_160_))
        script += opcodes.OP_EQUAL.hex()
    else:
        raise QtumException(f'unknown address type: {addrtype}')
    return script

def address_to_scripthash(addr):
    script = address_to_script(addr)
    return script_to_scripthash(script)


def script_to_scripthash(script):
    h = sha256(bytes.fromhex(script))[0:32]
    return bh2u(bytes(reversed(h)))

def public_key_to_p2pk_script(pubkey):
    return push_script(pubkey) + opcodes.OP_CHECKSIG.hex()


__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


def base_encode(v: bytes, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    assert base in (58, 43)
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c
    result = bytearray()
    while long_value >= base:
        div, mod = divmod(long_value, base)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0x00:
            nPad += 1
        else:
            break
    result.extend([chars[0]] * nPad)
    result.reverse()
    return result.decode('ascii')


def base_decode(v, length, base):
    """ decode v into a string of len bytes."""
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    assert base in (58, 43)
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        digit = chars.find(bytes([c]))
        if digit == -1:
            raise ValueError('Forbidden character {} for base {}'.format(c, base))
        long_value += digit * (base ** i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)


class InvalidChecksum(Exception):
    pass

def EncodeBase58Check(vchIn):
    hash = sha256d(vchIn)
    return base_encode(vchIn + hash[0:4], base=58)


def DecodeBase58Check(psz):
    vchRet = base_decode(psz, None, base=58)
    key = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = sha256d(key)
    cs32 = hash[0:4]
    if cs32 != csum:
        raise InvalidChecksum('expected {}, actual {}'.format(bh2u(cs32), bh2u(csum)))
    else:
        return key


# extended key export format for segwit

WIF_SCRIPT_TYPES = {
    'p2pkh': 0,
    'p2wpkh': 1,
    'p2wpkh-p2sh': 2,
    'p2sh': 5,
    'p2wsh': 6,
    'p2wsh-p2sh': 7
}
WIF_SCRIPT_TYPES_INV = inv_dict(WIF_SCRIPT_TYPES)


def serialize_privkey(secret: bytes, compressed: bool, txin_type: str, internal_use: bool=False) -> str:
    # we only export secrets inside curve range
    secret = ecc.ECPrivkey.normalize_secret_bytes(secret)
    if internal_use:
        prefix = bytes([(WIF_SCRIPT_TYPES[txin_type] + constants.net.WIF_PREFIX) & 255])
    else:
        prefix = bytes([constants.net.WIF_PREFIX])
    suffix = b'\01' if compressed else b''
    vchIn = prefix + secret + suffix
    base58_wif = EncodeBase58Check(vchIn)
    if internal_use:
        return base58_wif
    return '{}:{}'.format(txin_type, base58_wif)


def deserialize_privkey(key: str) -> Tuple[str, bytes, bool]:
    if is_minikey(key):
        return 'p2pkh', minikey_to_private_key(key), False

    txin_type = None
    if ':' in key:
        txin_type, key = key.split(sep=':', maxsplit=1)
        assert txin_type in WIF_SCRIPT_TYPES
    try:
        vch = DecodeBase58Check(key)
    except BaseException:
        neutered_privkey = str(key)[:3] + '..' + str(key)[-2:]
        raise Exception("cannot deserialize", neutered_privkey)

    if txin_type is None:
        # keys exported in version 3.0.x encoded script type in first byte
        prefix_value = vch[0] - constants.net.WIF_PREFIX
        try:
            txin_type = WIF_SCRIPT_TYPES_INV[prefix_value]
        except KeyError:
            raise Exception('invalid prefix ({}) for WIF key (1)'.format(vch[0]))
    else:
        # all other keys must have a fixed first byte
        if vch[0] != constants.net.WIF_PREFIX:
            raise Exception('invalid prefix ({}) for WIF key (2)'.format(vch[0]))

    if len(vch) not in [33, 34]:
        raise Exception('invalid vch len for WIF key: {}'.format(len(vch)))
    compressed = len(vch) == 34
    secret_bytes = vch[1:33]
    # we accept secrets outside curve range; cast into range here:
    secret_bytes = ecc.ECPrivkey.normalize_secret_bytes(secret_bytes)
    return txin_type, secret_bytes, compressed


def is_compressed(sec):
    return deserialize_privkey(sec)[2]


def address_from_private_key(sec):
    txin_type, privkey, compressed = deserialize_privkey(sec)
    public_key = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
    address = pubkey_to_address(txin_type, public_key)
    return address


def is_segwit_address(addr, *, net=None):
    if net is None: net = constants.net
    try:
        witver, witprog = segwit_addr.decode(net.SEGWIT_HRP, addr)
    except Exception as e:
        return False
    return witprog is not None


def is_b58_address(addr, *, net=None):
    if net is None: net = constants.net
    try:
        addrtype, h = b58_address_to_hash160(addr)
    except Exception as e:
        return False
    if addrtype not in [net.ADDRTYPE_P2PKH, net.ADDRTYPE_P2SH]:
        return False
    return addr == hash160_to_b58_address(h, addrtype)

def is_address(addr, *, net=None):
    if net is None: net = constants.net
    return is_segwit_address(addr, net=net) \
           or is_b58_address(addr, net=net)

def is_p2pkh(addr):
    if is_address(addr):
        addrtype, h = b58_address_to_hash160(addr)
        return addrtype == constants.net.ADDRTYPE_P2PKH


def is_p2sh(addr):
    if is_address(addr):
        addrtype, h = b58_address_to_hash160(addr)
        return addrtype == constants.net.ADDRTYPE_P2SH


def is_private_key(key):
    try:
        k = deserialize_privkey(key)
        return k is not False
    except:
        return False


def is_hash160(addr):
    if not addr:
        return False
    if not isinstance(addr, str):
        return False
    if not len(addr) == 40:
        return False
    for char in addr:
        if (char < '0' or char > '9') and (char < 'A' or char > 'F') and (char < 'a' or char > 'f'):
            return False
    return True



########### end pywallet functions #######################

def is_minikey(text):
    # Minikeys are typically 22 or 30 characters, but this routine
    # permits any length of 20 or more provided the minikey is valid.
    # A valid minikey must begin with an 'S', be in base58, and when
    # suffixed with '?' have its SHA256 hash begin with a zero byte.
    # They are widely used in Casascius physical bitoins.
    return (len(text) >= 20 and text[0] == 'S'
            and all(ord(c) in __b58chars for c in text)
            and sha256(text + '?')[0] == 0x00)


def minikey_to_private_key(text):
    return sha256(text)


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
        return self._read_nbytes(self._read_varint())

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


def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00' * 32
    return hash_encode(sha256d(bfh(serialize_header(header))))


def serialize_header(res):
    sig_length = len(res.get('sig'))//2
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4) \
        + rev_hex(res.get('hash_state_root')) \
        + rev_hex(res.get('hash_utxo_root')) \
        + rev_hex(res.get('hash_prevout_stake')) \
        + int_to_hex(int(res.get('hash_prevout_n')), 4) \
        + var_int(sig_length) \
        + (res.get('sig'))
    # print('serialize_header', res, '\n', s)
    return s


def deserialize_header(s, height):
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


def read_a_raw_header_from_chunk(data, start):
    deserializer = Deserializer(data, start=start+BASIC_HEADER_SIZE)
    sig_length = deserializer.read_varint()
    cursor = deserializer.cursor + sig_length
    return data[start: cursor], cursor


def is_pos(header):
    hash_prevout_stake = header.get('hash_prevout_stake', None)
    hash_prevout_n = header.get('hash_prevout_n', 0)
    return hash_prevout_stake and (
        hash_prevout_stake != '0000000000000000000000000000000000000000000000000000000000000000'
        or hash_prevout_n != 0xffffffff)

# nbits to target
def uint256_from_compact(bits):
    bitsN = (bits >> 24) & 0xff
    bitsBase = bits & 0xffffff
    target = bitsBase << (8 * (bitsN - 3))
    return target


# target to nbits
def compact_from_uint256(target):
    c = ("%064x" % target)[2:]
    while c[:2] == '00' and len(c) > 6:
        c = c[2:]
    bitsN, bitsBase = len(c) // 2, int.from_bytes(bfh(c[:6]), byteorder='big')
    if bitsBase >= 0x800000:
        bitsN += 1
        bitsBase >>= 8
    new_bits = bitsN << 24 | bitsBase
    return new_bits


def qtum_addr_to_bitcoin_addr(qtum_addr):
    addr_type, hash160 = b58_address_to_hash160(qtum_addr)
    if addr_type == constants.net.ADDRTYPE_P2PKH:
        return hash160_to_b58_address(hash160, addrtype=constants.net.BITCOIN_ADDRTYPE_P2PKH)
    elif addr_type == constants.net.ADDRTYPE_P2SH:
        return hash160_to_b58_address(hash160, addrtype=constants.net.BITCOIN_ADDRTYPE_P2SH)


def eth_abi_encode(abi, args):
    """
    >> abi = {"constant":True,"inputs":[{"name":"","type":"address"}],
"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"}
    >> eth_abi_encode(abi, ['9d3d4cc1986d81f9109f2b091b7732e7d9bcf63b'])
    >> '70a082310000000000000000000000009d3d4cc1986d81f9109f2b091b7732e7d9bcf63b'
    ## address must be lower case
    :param abi: dict
    :param args: list
    :return: str
    """
    if not abi:
        return "00"
    types = list([inp['type'] for inp in abi.get('inputs', [])])
    if abi.get('name'):
        result = function_abi_to_4byte_selector(abi) + encode_abi(types, args)
    else:
        result = encode_abi(types, args)
    return bh2u(result)
