# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import hashlib
import hmac
from typing import List
from eth_abi import encode_abi
from eth_utils import function_abi_to_4byte_selector

from .util import bfh, bh2u, assert_bytes, to_bytes, inv_dict, print_error, QtumException
from .util import unpack_uint16_from, unpack_uint32_from, unpack_uint64_from, unpack_int32_from, unpack_int64_from
from . import version
from . import constants
from . import segwit_addr
from . import ecc
from .crypto import Hash, sha256, hash_160

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
FEERATE_STATIC_VALUES = [410000, 500000, 600000, 700000, 800000, 1000000, 1300000, 180000, 2000000, 3000000]

FEE_TARGETS = [25, 10, 5, 2]

COINBASE_MATURITY = 500
COIN = 100000000
TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 100664516

# supported types of transction outputs
TYPE_ADDRESS = 0
TYPE_PUBKEY  = 1
TYPE_SCRIPT  = 2
TYPE_STAKE = 3


def rev_hex(s):
    return bh2u(bfh(s)[::-1])


def int_to_hex(i: int, length: int=1) -> str:
    assert isinstance(i, int)
    range_size = pow(256, length)
    if i < -range_size / 2 or i >= range_size:
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


def op_push(i: int) -> str:
    if i < 0x4c:  # OP_PUSHDATA1
        return int_to_hex(i)
    elif i <= 0xff:
        return '4c' + int_to_hex(i)
    elif i <= 0xffff:
        return '4d' + int_to_hex(i,2)
    else:
        return '4e' + int_to_hex(i,4)


def push_script(data: str) -> str:
    """Returns pushed data to the script, automatically
    choosing canonical opcodes depending on the length of the data.
    hex -> hex

    ported from https://github.com/btcsuite/btcd/blob/fdc2bc867bda6b351191b5872d2da8270df00d13/txscript/scriptbuilder.go#L128
    """
    data = bfh(data)
    from .transaction import opcodes

    data_len = len(data)

    # "small integer" opcodes
    if data_len == 0 or data_len == 1 and data[0] == 0:
        return bh2u(bytes([opcodes.OP_0]))
    elif data_len == 1 and data[0] <= 16:
        return bh2u(bytes([opcodes.OP_1 - 1 + data[0]]))
    elif data_len == 1 and data[0] == 0x81:
        return bh2u(bytes([opcodes.OP_1NEGATE]))

    return op_push(data_len) + bh2u(data)

def add_number_to_script(i: int) -> bytes:
    return bfh(push_script(script_num_to_hex(i)))


hash_encode = lambda x: bh2u(x[::-1])
hash_decode = lambda x: bfh(x)[::-1]
hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).digest()


def is_new_seed(x, prefix=version.SEED_PREFIX):
    from . import mnemonic
    x = mnemonic.normalize_text(x)
    s = bh2u(hmac_sha_512(b"Seed version", x.encode('utf8')))
    return s.startswith(prefix)


def is_old_seed(seed):
    from . import old_mnemonic
    words = seed.strip().split()
    try:
        old_mnemonic.mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        seed = bfh(seed)
        is_hex = (len(seed) == 16 or len(seed) == 32)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))


def seed_type(x):
    # if is_old_seed(x):
    #     return 'old'
    if is_new_seed(x):
        return 'standard'
    elif is_new_seed(x, version.SEED_PREFIX_SW):
        return 'segwit'
    # elif is_new_seed(x, version.SEED_PREFIX_2FA):
    #     # disable 2fa for now
    #     return '2fa'
    return ''

is_seed = lambda x: bool(seed_type(x))


############ functions from pywallet #####################


def hash160_to_b58_address(h160: bytes, addrtype, witness_program_version=1):
    s = bytes([addrtype])
    s += h160
    return base_encode(s+Hash(s)[0:4], base=58)


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


def address_to_script(addr):
    witver, witprog = segwit_addr.decode(constants.net.SEGWIT_HRP, addr)
    if witprog is not None:
        assert (0 <= witver <= 16)
        OP_n = witver + 0x50 if witver > 0 else 0
        script = bh2u(bytes([OP_n]))
        script += push_script(bh2u(bytes(witprog)))
        return script
    addrtype, hash_160 = b58_address_to_hash160(addr)
    if addrtype == constants.net.ADDRTYPE_P2PKH:
        script = '76a9'                                      # op_dup, op_hash_160
        script += push_script(bh2u(hash_160))
        script += '88ac'                                     # op_equalverify, op_checksig
    elif addrtype == constants.net.ADDRTYPE_P2SH:
        script = 'a9'                                        # op_hash_160
        script += push_script(bh2u(hash_160))
        script += '87'                                       # op_equal
    else:
        raise Exception('unknown address type')
    return script

def address_to_scripthash(addr):
    script = address_to_script(addr)
    return script_to_scripthash(script)


def script_to_scripthash(script):
    h = sha256(bytes.fromhex(script))[0:32]
    return bh2u(bytes(reversed(h)))

def public_key_to_p2pk_script(pubkey):
    script = push_script(pubkey)
    script += 'ac'
    return script


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
    hash = Hash(vchIn)
    return base_encode(vchIn + hash[0:4], base=58)


def DecodeBase58Check(psz):
    vchRet = base_decode(psz, None, base=58)
    key = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = Hash(key)
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


PURPOSE48_SCRIPT_TYPES = {
    'p2wsh-p2sh': 1,  # specifically multisig
    'p2wsh': 2,       # specifically multisig
}
PURPOSE48_SCRIPT_TYPES_INV = inv_dict(PURPOSE48_SCRIPT_TYPES)


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


def deserialize_privkey(key: str) -> (str, bytes, bool):
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


def is_segwit_address(addr):
    try:
        witver, witprog = segwit_addr.decode(constants.net.SEGWIT_HRP, addr)
        return witprog is not None
    except (BaseException,) as e:
        return False


def is_b58_address(addr):
    try:
        addrtype, h = b58_address_to_hash160(addr)
    except Exception as e:
        return False
    if addrtype not in [constants.net.ADDRTYPE_P2PKH, constants.net.ADDRTYPE_P2SH]:
        return False
    return addr == hash160_to_b58_address(h, addrtype)


def is_address(addr):
    return is_segwit_address(addr) or is_b58_address(addr)


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


###################################### BIP32 ##############################

BIP32_PRIME = 0x80000000


def protect_against_invalid_ecpoint(func):
    def func_wrapper(*args):
        n = args[-1]
        while True:
            is_prime = n & BIP32_PRIME
            try:
                return func(*args[:-1], n=n)
            except ecc.InvalidECPointException:
                print_error('bip32 protect_against_invalid_ecpoint: skipping index')
                n += 1
                is_prime2 = n & BIP32_PRIME
                if is_prime != is_prime2: raise OverflowError()
    return func_wrapper

# Child private key derivation function (from master private key)
# k = master private key (32 bytes)
# c = master chain code (extra entropy for key derivation) (32 bytes)
# n = the index of the key we want to derive. (only 32 bits will be used)
# If n is hardened (i.e. the 32nd bit is set), the resulting private key's
#  corresponding public key can NOT be determined without the master private key.
# However, if n is not hardened, the resulting private key's corresponding
#  public key can be determined without the master private key.
@protect_against_invalid_ecpoint
def CKD_priv(k, c, n):
    if n < 0: raise ValueError('the bip32 index needs to be non-negative')
    is_prime = n & BIP32_PRIME
    return _CKD_priv(k, c, bfh(rev_hex(int_to_hex(n,4))), is_prime)


def _CKD_priv(k, c, s, is_prime):
    try:
        keypair = ecc.ECPrivkey(k)
    except ecc.InvalidECPointException as e:
        raise QtumException('Impossible xprv (not within curve order)') from e
    cK = keypair.get_public_key_bytes(compressed=True)
    data = bytes([0]) + k + s if is_prime else cK + s
    I = hmac.new(c, data, hashlib.sha512).digest()
    I_left = ecc.string_to_number(I[0:32])
    k_n = (I_left + ecc.string_to_number(k)) % ecc.CURVE_ORDER
    if I_left >= ecc.CURVE_ORDER or k_n == 0:
        raise ecc.InvalidECPointException()
    k_n = ecc.number_to_string(k_n, ecc.CURVE_ORDER)
    c_n = I[32:]
    return k_n, c_n

# Child public key derivation function (from public key only)
# K = master public key
# c = master chain code
# n = index of key we want to derive
# This function allows us to find the nth public key, as long as n is
#  not hardened. If n is hardened, we need the master private key to find it.
@protect_against_invalid_ecpoint
def CKD_pub(cK, c, n):
    if n < 0: raise ValueError('the bip32 index needs to be non-negative')
    if n & BIP32_PRIME:
        raise Exception('CKD_pub error')
    return _CKD_pub(cK, c, bfh(rev_hex(int_to_hex(n,4))))

# helper function, callable with arbitrary string
# note: 's' does not need to fit into 32 bits here! (c.f. trustedcoin billing)
def _CKD_pub(cK, c, s):
    I = hmac.new(c, cK + s, hashlib.sha512).digest()
    pubkey = ecc.ECPrivkey(I[0:32]) + ecc.ECPubkey(cK)
    if pubkey.is_at_infinity():
        raise ecc.InvalidECPointException()
    cK_n = pubkey.get_public_key_bytes(compressed=True)
    c_n = I[32:]
    return cK_n, c_n


def xprv_header(xtype, *, net=None):
    if net is None:
        net = constants.net
    return bfh("%08x" % (net.XPRV_HEADERS[xtype]))


def xpub_header(xtype, *, net=None):
    if net is None:
        net = constants.net
    return bfh("%08x" % (net.XPUB_HEADERS[xtype]))


def serialize_xprv(xtype, c, k, depth=0, fingerprint=b'\x00'*4,
                   child_number=b'\x00'*4, *, net=None):
    if not ecc.is_secret_within_curve_range(k):
        raise Exception('Impossible xprv (not within curve order)')
    xprv = xprv_header(xtype, net=net) + bytes([depth]) + fingerprint + child_number + c + bytes([0]) + k
    return EncodeBase58Check(xprv)


def serialize_xpub(xtype, c, cK, depth=0, fingerprint=b'\x00'*4, child_number=b'\x00'*4, *, net=None):
    xpub = xpub_header(xtype, net=net) + bytes([depth]) + fingerprint + child_number + c + cK
    return EncodeBase58Check(xpub)


def deserialize_xkey(xkey, prv, *, net=None):
    if net is None:
        net = constants.net
    xkey = DecodeBase58Check(xkey)
    if not xkey or len(xkey) != 78:
        raise Exception('Invalid xkey', xkey)
    depth = xkey[4]
    fingerprint = xkey[5:9]
    child_number = xkey[9:13]
    c = xkey[13:13+32]
    header = int('0x' + bh2u(xkey[0:4]), 16)
    headers = net.XPRV_HEADERS if prv else net.XPUB_HEADERS
    if header not in headers.values():
        raise Exception('Invalid xpub format', hex(header))
    xtype = list(headers.keys())[list(headers.values()).index(header)]
    n = 33 if prv else 32
    K_or_k = xkey[13+n:]
    if prv and not ecc.is_secret_within_curve_range(K_or_k):
        raise Exception('Impossible xprv (not within curve order)')
    return xtype, depth, fingerprint, child_number, c, K_or_k


def deserialize_xpub(xkey, *, net=None):
    return deserialize_xkey(xkey, False, net=net)

def deserialize_xprv(xkey, *, net=None):
    return deserialize_xkey(xkey, True, net=net)


def xpub_type(x):
    return deserialize_xpub(x)[0]

def is_xpub(text):
    try:
        deserialize_xpub(text)
        return True
    except:
        return False


def is_xprv(text):
    try:
        deserialize_xprv(text)
        return True
    except:
        return False


def xpub_from_xprv(xprv):
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    cK = ecc.ECPrivkey(k).get_public_key_bytes(compressed=True)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def bip32_root(seed, xtype):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k = I[0:32]
    master_c = I[32:]
    # create xprv first, as that will check if master_k is within curve order
    xprv = serialize_xprv(xtype, master_c, master_k)
    cK = ecc.ECPrivkey(master_k).get_public_key_bytes(compressed=True)
    xpub = serialize_xpub(xtype, master_c, cK)
    return xprv, xpub


def xpub_from_pubkey(xtype, cK):
    if cK[0] not in (0x02, 0x03):
        raise ValueError('Unexpected first byte: {}'.format(cK[0]))
    return serialize_xpub(xtype, b'\x00'*32, cK)


def bip32_derivation(s):
    assert s.startswith('m/')
    s = s[2:]
    for n in s.split('/'):
        if n == '': continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        yield i


def convert_bip32_path_to_list_of_uint32(n: str) -> List[int]:
    """Convert bip32 path to list of uint32 integers with prime flags
    m/0/-1/1' -> [0, 0x80000001, 0x80000001]

    based on code in trezorlib
    """
    path = []
    for x in n.split('/')[1:]:
        if x == '': continue
        prime = 0
        if x.endswith("'"):
            x = x.replace('\'', '')
            prime = BIP32_PRIME
        if x.startswith('-'):
            prime = BIP32_PRIME
        path.append(abs(int(x)) | prime)
    return path


def is_bip32_derivation(x):
    try:
        [i for i in bip32_derivation(x)]
        return True
    except :
        return False

def bip32_private_derivation(xprv, branch, sequence):
    assert sequence.startswith(branch)
    if branch == sequence:
        return xprv, xpub_from_xprv(xprv)
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        parent_k = k
        k, c = CKD_priv(k, c, i)
        depth += 1
    parent_cK = ecc.ECPrivkey(parent_k).get_public_key_bytes(compressed=True)
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X"%i)
    cK = ecc.ECPrivkey(k).get_public_key_bytes(compressed=True)
    xpub = serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)
    xprv = serialize_xprv(xtype, c, k, depth, fingerprint, child_number)
    return xprv, xpub


def bip32_public_derivation(xpub, branch, sequence):
    xtype, depth, fingerprint, child_number, c, cK = deserialize_xpub(xpub)
    assert sequence.startswith(branch)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n)
        parent_cK = cK
        cK, c = CKD_pub(cK, c, i)
        depth += 1
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X"%i)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def bip32_private_key(sequence, k, chain):
    for i in sequence:
        k, chain = CKD_priv(k, chain, i)
    return k


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
    return hash_encode(Hash(bfh(serialize_header(header))))


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
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
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
    bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
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
