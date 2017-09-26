from struct import pack, unpack
import hashlib
import time
import sys
import traceback

import electrum
from electrum import bitcoin
from electrum.bitcoin import TYPE_ADDRESS, int_to_hex, var_int
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.keystore import Hardware_KeyStore, parse_xpubkey
from electrum.transaction import push_script, Transaction
from ..hw_wallet import HW_PluginBase
from electrum.util import format_satoshis_plain, print_error, is_verbose, bfh, bh2u

try:
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI, DongleWait
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script, get_p2sh_input_script
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = is_verbose
except ImportError:
    BTCHIP = False

class Ledger_Client():
    def __init__(self, hidDevice):
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False

    def is_pairable(self):
        return True

    def close(self):
        self.dongleObject.dongle.close()

    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        return True

    def label(self):
        return ""

    def i4b(self, x):
        return pack('>I', x)        

    def get_xpub(self, bip32_path):
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler.show_message("Computing master public key")
        try:
            xtype = 'segwit_p2sh' if bip32_path.startswith("m/49'/") else 'standard'
            splitPath = bip32_path.split('/')
            if splitPath[0] == 'm':
                splitPath = splitPath[1:]
                bip32_path = bip32_path[2:]
            fingerprint = 0
            if len(splitPath) > 1:
                prevPath = "/".join(splitPath[0:len(splitPath) - 1])
                nodeData = self.dongleObject.getWalletPublicKey(prevPath)
                publicKey = compress_public_key(nodeData['publicKey'])
                h = hashlib.new('ripemd160')
                h.update(hashlib.sha256(publicKey).digest())
                fingerprint = unpack(">I", h.digest()[0:4])[0]
            nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
            publicKey = compress_public_key(nodeData['publicKey'])
            depth = len(splitPath)
            lastChild = splitPath[len(splitPath) - 1].split('\'')
            childnum = int(lastChild[0]) if len(lastChild) == 1 else 0x80000000 | int(lastChild[0])
            xpub = bitcoin.serialize_xpub(xtype, nodeData['chainCode'], publicKey, depth, self.i4b(fingerprint), self.i4b(childnum))
            return xpub
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            #print_error(e)
            return None

    def has_detached_pin_support(self, client):
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except BTChipException as e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client):
        try:
            # Invalid SET OPERATION MODE to verify the PIN status
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException as e:
            if (e.sw == 0x6982):
                return False
            if (e.sw == 0x6A80):
                return True
            raise e

    def supports_multi_output(self):
        return self.multiOutputSupported

    def perform_hw1_preflight(self):
        try:
            firmware = self.dongleObject.getFirmwareVersion()['version'].split(".")
            self.multiOutputSupported = int(firmware[0]) >= 1 and int(firmware[1]) >= 1 and int(firmware[2]) >= 4
            if not checkFirmware(firmware):
                self.dongleObject.dongle.close()
                raise Exception("HW1 firmware version too old. Please update at https://www.ledgerwallet.com")
            try:
                self.dongleObject.getOperationMode()
            except BTChipException as e:
                if (e.sw == 0x6985):
                    self.dongleObject.dongle.close()
                    self.handler.get_setup( )
                    # Acquire the new client on the next run
                else:
                    raise e
            if self.has_detached_pin_support(self.dongleObject) and not self.is_pin_validated(self.dongleObject) and (self.handler is not None):
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts != 1:
                    msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
                else:
                    msg = "Enter your Ledger PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
                confirmed, p, pin = self.