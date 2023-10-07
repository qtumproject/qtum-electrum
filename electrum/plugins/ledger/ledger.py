import os
from struct import pack, unpack
import hashlib
import sys
import traceback
from typing import Optional, Tuple
from collections import defaultdict

from electrum import ecc
from electrum import bip32
from electrum import constants
from electrum.crypto import hash_160
from electrum.bitcoin import int_to_hex, var_int, is_segwit_script_type, push_data, is_b58_address
from electrum.bip32 import BIP32Node, convert_bip32_intpath_to_strpath
from electrum.i18n import _
from electrum.keystore import Hardware_KeyStore
from electrum.transaction import Transaction, decode_opsender_script, update_opsender_sig
from electrum.wallet import Standard_Wallet
from electrum.util import bfh, versiontuple, UserFacingException
from electrum.base_wizard import ScriptTypeNotSupported
from electrum.logging import get_logger
from electrum.plugin import runs_in_hwd_thread, Device

from ..hw_wallet import HW_PluginBase, HardwareClientBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch, LibraryFoundButUnusable


_logger = get_logger(__name__)


try:
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI, DongleWait, DongleServer
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script, get_p2sh_input_script
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = False
except ImportError as e:
    if not (isinstance(e, ModuleNotFoundError) and e.name == 'btchip'):
        _logger.exception('error importing ledger plugin deps')
    BTCHIP = False

if BTCHIP:
    try:
        from btchip import QTUM_OPSENDER_SUPPORT
    except ImportError:
        raise Exception("Please uninstall btchip-python and install btchip-qtum OR use a clean virtualenv")

MSG_NEEDS_FW_UPDATE_GENERIC = _('Firmware version too old. Please update at') + \
                      ' https://www.ledgerwallet.com'
MSG_NEEDS_FW_UPDATE_SEGWIT = _('Firmware version (or "Qtum" app) too old for Segwit support. Please update at') + \
                      ' https://www.ledgerwallet.com'
MSG_NEEDS_FW_UPDATE_OPSENDER = _('Firmware version (or "Qtum" app) too old for OpSender support. Please update at') + \
                      ' https://www.ledgerwallet.com'
MULTI_OUTPUT_SUPPORT = '1.1.4'
SEGWIT_SUPPORT = '1.1.10'
SEGWIT_SUPPORT_SPECIAL = '1.0.4'
SEGWIT_TRUSTEDINPUTS = '1.4.0'
OP_SENDER_SUPPORT = '1.5.0'


def test_pin_unlocked(func):
    """Function decorator to test the Ledger for being unlocked, and if not,
    raise a human-readable exception.
    """
    def catch_exception(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except BTChipException as e:
            if e.sw == 0x6982:
                raise UserFacingException(_('Your Ledger is locked. Please unlock it.'))
            else:
                raise
    return catch_exception


class Ledger_Client(HardwareClientBase):
    def __init__(self, hidDevice, *, product_key: Tuple[int, int],
                 plugin: HW_PluginBase):
        HardwareClientBase.__init__(self, plugin=plugin)
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False
        self._product_key = product_key
        self._soft_device_id = None

    def is_pairable(self):
        return True

    @runs_in_hwd_thread
    def close(self):
        self.dongleObject.dongle.close()

    def is_initialized(self):
        return True

    @runs_in_hwd_thread
    def get_soft_device_id(self):
        if self._soft_device_id is None:
            # modern ledger can provide xpub without user interaction
            # (hw1 would prompt for PIN)
            if not self.is_hw1():
                self._soft_device_id = self.request_root_fingerprint_from_device()
        return self._soft_device_id

    def is_hw1(self) -> bool:
        return self._product_key[0] == 0x2581

    def device_model_name(self):
        return LedgerPlugin.device_name_from_product_key(self._product_key)

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        try:
            self.dongleObject.getFirmwareVersion()
        except BaseException:
            return False
        return True

    @runs_in_hwd_thread
    @test_pin_unlocked
    def get_xpub(self, bip32_path, xtype):
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler.show_message("Computing master public key")
        if xtype in ['p2wpkh', 'p2wsh'] and not self.supports_native_segwit():
            raise UserFacingException(MSG_NEEDS_FW_UPDATE_SEGWIT)
        if xtype in ['p2wpkh-p2sh', 'p2wsh-p2sh'] and not self.supports_segwit():
            raise UserFacingException(MSG_NEEDS_FW_UPDATE_SEGWIT)
        bip32_path = bip32.normalize_bip32_derivation(bip32_path)
        bip32_intpath = bip32.convert_bip32_path_to_list_of_uint32(bip32_path)
        bip32_path = bip32_path[2:]  # cut off "m/"
        if len(bip32_intpath) >= 1:
            prevPath = bip32.convert_bip32_intpath_to_strpath(bip32_intpath[:-1])[2:]
            nodeData = self.dongleObject.getWalletPublicKey(prevPath)
            publicKey = compress_public_key(nodeData['publicKey'])
            fingerprint_bytes = hash_160(publicKey)[0:4]
            childnum_bytes = bip32_intpath[-1].to_bytes(length=4, byteorder="big")
        else:
            fingerprint_bytes = bytes(4)
            childnum_bytes = bytes(4)
        nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
        publicKey = compress_public_key(nodeData['publicKey'])
        depth = len(bip32_intpath)
        return BIP32Node(xtype=xtype,
                         eckey=ecc.ECPubkey(bytes(publicKey)),
                         chaincode=nodeData['chainCode'],
                         depth=depth,
                         fingerprint=fingerprint_bytes,
                         child_number=childnum_bytes).to_xpub()

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

    def supports_segwit(self):
        return self.segwitSupported

    def supports_native_segwit(self):
        return self.nativeSegwitSupported

    def supports_segwit_trustedInputs(self):
        return self.segwitTrustedInputs

    def supports_op_sender(self):
        return self.opSenderSupported

    @runs_in_hwd_thread
    def perform_hw1_preflight(self):
        try:
            firmwareInfo = self.dongleObject.getFirmwareVersion()
            firmware = firmwareInfo['version']
            self.multiOutputSupported = versiontuple(firmware) >= versiontuple(MULTI_OUTPUT_SUPPORT)
            self.nativeSegwitSupported = versiontuple(firmware) >= versiontuple(SEGWIT_SUPPORT)
            self.segwitSupported = self.nativeSegwitSupported or (firmwareInfo['specialVersion'] == 0x20 and versiontuple(firmware) >= versiontuple(SEGWIT_SUPPORT_SPECIAL))
            self.segwitTrustedInputs = versiontuple(firmware) >= versiontuple(SEGWIT_TRUSTEDINPUTS)
            self.opSenderSupported = versiontuple(firmware) >= versiontuple(OP_SENDER_SUPPORT)

            if not checkFirmware(firmwareInfo):
                self.close()
                raise UserFacingException(MSG_NEEDS_FW_UPDATE_GENERIC)
            try:
                self.dongleObject.getOperationMode()
            except BTChipException as e:
                if (e.sw == 0x6985):
                    self.close()
                    self.handler.get_setup( )
                    # Acquire the new client on the next run
                else:
                    raise e
            if self.has_detached_pin_support(self.dongleObject) and not self.is_pin_validated(self.dongleObject):
                assert self.handler, "no handler for client"
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts != 1:
                    msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
                else:
                    msg = "Enter your Ledger PIN - WARNING : LAST ATTEMPT. If the PIN is not correct, the dongle will be wiped."
                confirmed, p, pin = self.password_dialog(msg)
                if not confirmed:
                    raise UserFacingException('Aborted by user - please unplug the dongle and plug it again before retrying')
                pin = pin.encode()
                self.dongleObject.verifyPin(pin)
        except BTChipException as e:
            if (e.sw == 0x6faa):
                raise UserFacingException("Dongle is temporarily locked - please unplug it and replug it again")
            if ((e.sw & 0xFFF0) == 0x63c0):
                raise UserFacingException("Invalid PIN - please unplug the dongle and plug it again before retrying")
            if e.sw == 0x6f00 and e.message == 'Invalid channel':
                # based on docs 0x6f00 might be a more general error, hence we also compare message to be sure
                raise UserFacingException("Invalid channel.\n"
                                          "Please make sure that 'Browser support' is disabled on your device.")
            raise e

    @runs_in_hwd_thread
    def checkDevice(self):
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except BTChipException as e:
                if (e.sw == 0x6d00 or e.sw == 0x6700):
                    raise UserFacingException(_("Device not in Qtum mode")) from e
                raise e
            self.preflightDone = True

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response


class Ledger_KeyStore(Hardware_KeyStore):
    hw_type = 'ledger'
    device = 'Ledger'

    plugin: 'LedgerPlugin'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.force_watching_only = False
        self.signing = False
        self.cfg = d.get('cfg', {'mode': 0})

    def dump(self):
        obj = Hardware_KeyStore.dump(self)
        obj['cfg'] = self.cfg
        return obj

    def get_client(self):
        return self.plugin.get_client(self).dongleObject

    def get_client_electrum(self) -> Optional[Ledger_Client]:
        return self.plugin.get_client(self)

    def give_error(self, message, clear_client = False):
        _logger.info(message)
        if not self.signing:
            self.handler.show_error(message)
        else:
            self.signing = False
        if clear_client:
            self.client = None
        raise UserFacingException(message)

    def set_and_unset_signing(func):
        """Function decorator to set and unset self.signing."""
        def wrapper(self, *args, **kwargs):
            try:
                self.signing = True
                return func(self, *args, **kwargs)
            finally:
                self.signing = False
        return wrapper

    def decrypt_message(self, pubkey, message, password):
        raise UserFacingException(_('Encryption and decryption are currently not supported for {}').format(self.device))

    @runs_in_hwd_thread
    @test_pin_unlocked
    @set_and_unset_signing
    def sign_message(self, sequence, message, password, *, script_type=None):
        message = message.encode('utf8')
        message_hash = hashlib.sha256(message).hexdigest().upper()
        # prompt for the PIN before displaying the dialog if necessary
        client_ledger = self.get_client()
        client_electrum = self.get_client_electrum()
        address_path = self.get_derivation_prefix()[2:] + "/%d/%d"%sequence
        self.handler.show_message("Signing message ...\r\nMessage hash: "+message_hash)
        try:
            info = client_ledger.signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                # do the authenticate dialog and get pin:
                pin = self.handler.get_auth(info, client=client_electrum)
                if not pin:
                    raise UserWarning(_('Cancelled by user'))
                pin = str(pin).encode()
            signature = client_ledger.signMessageSign(pin)
        except BTChipException as e:
            if e.sw == 0x6a80:
                self.give_error("Unfortunately, this message cannot be signed by the Ledger wallet. Only alphanumerical messages shorter than 140 characters are supported. Please remove any extra characters (tab, carriage return) and retry.")
            elif e.sw == 0x6985:  # cancelled by user
                return b''
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            else:
                self.give_error(e, True)
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return b''
        except Exception as e:
            self.give_error(e, True)
        finally:
            self.handler.finished()
        # Parse the ASN.1 signature
        rLength = signature[3]
        r = signature[4 : 4 + rLength]
        sLength = signature[4 + rLength + 1]
        s = signature[4 + rLength + 2:]
        if rLength == 33:
            r = r[1:]
        if sLength == 33:
            s = s[1:]
        # And convert it
        # Pad r and s points with 0x00 bytes when the point is small to get valid signature.
        r_padded = bytes([0x00]) * (32 - len(r)) + r
        s_padded = bytes([0x00]) * (32 - len(s)) + s

        return bytes([27 + 4 + (signature[0] & 0x01)]) + r_padded + s_padded

    @runs_in_hwd_thread
    @test_pin_unlocked
    @set_and_unset_signing
    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return

        inputs = []
        inputsPaths = []
        chipInputs = []
        redeemScripts = []
        changePath = ""
        output = None
        p2shTransaction = False
        segwitTransaction = False
        opsenderTransaction = False
        pin = ""
        client_ledger = self.get_client() # prompt for the PIN before displaying the dialog if necessary
        client_electrum = self.get_client_electrum()
        assert client_electrum

        for i, txout in enumerate(tx.outputs()):
            decoded = decode_opsender_script(txout.scriptpubkey)
            if decoded is not None:
                opsenderTransaction = True
                break
        if opsenderTransaction and not client_electrum.supports_op_sender():
            self.give_error(MSG_NEEDS_FW_UPDATE_OPSENDER)
            return

        # Fetch inputs of the transaction to sign
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                self.give_error("Coinbase not supported")     # should never happen

            if txin.script_type in ['p2sh']:
                p2shTransaction = True

            if txin.script_type in ['p2wpkh-p2sh', 'p2wsh-p2sh']:
                if not client_electrum.supports_segwit():
                    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True

            if txin.script_type in ['p2wpkh', 'p2wsh']:
                if not client_electrum.supports_native_segwit():
                    self.give_error(MSG_NEEDS_FW_UPDATE_SEGWIT)
                segwitTransaction = True

            my_pubkey, full_path = self.find_my_pubkey_in_txinout(txin)
            if not full_path:
                self.give_error("No matching pubkey for sign_transaction")  # should never happen
            full_path = convert_bip32_intpath_to_strpath(full_path)[2:]

            redeemScript = Transaction.get_preimage_script(txin)
            txin_prev_tx = txin.utxo
            if txin_prev_tx is None and not txin.is_segwit():
                raise UserFacingException(_('Missing previous tx for legacy input.'))
            txin_prev_tx_raw = txin_prev_tx.serialize() if txin_prev_tx else None
            inputs.append([txin_prev_tx_raw,
                           txin.prevout.out_idx,
                           redeemScript,
                           txin.prevout.txid.hex(),
                           my_pubkey,
                           txin.nsequence,
                           txin.value_sats()])
            inputsPaths.append(full_path)

        # Sanity check
        if p2shTransaction:
            for txin in tx.inputs():
                if txin.script_type != 'p2sh':
                    self.give_error("P2SH / regular input mixed in same transaction not supported") # should never happen

        txOutput = var_int(len(tx.outputs()))
        for o in tx.outputs():
            txOutput += int_to_hex(o.value, 8)
            script = o.scriptpubkey.hex()
            txOutput += var_int(len(script)//2)
            txOutput += script
        txOutput = bfh(txOutput)

        if not client_electrum.supports_multi_output():
            if len(tx.outputs()) > 2:
                self.give_error("Transaction with more than 2 outputs not supported")

        for txout in tx.outputs():
            if client_electrum.is_hw1() and txout.address and not is_b58_address(txout.address):
                self.give_error(_("This {} device can only send to base58 addresses.").format(self.device))

        # don't restrict tx output
        # for txout in tx.outputs():
        #     if not txout.address:
        #         if client_electrum.is_hw1():
        #             self.give_error(_("Only address outputs are supported by {}").format(self.device))
        #         # note: max_size based on https://github.com/LedgerHQ/ledger-app-btc/commit/3a78dee9c0484821df58975803e40d58fbfc2c38#diff-c61ccd96a6d8b54d48f54a3bc4dfa7e2R26
        #         validate_op_return_output(txout, max_size=190)

        # Output "change" detection
        # - only one output and one change is authorized (for hw.1 and nano)
        # - at most one output can bypass confirmation (~change) (for all)
        # mark only one output as change
        if not p2shTransaction:
            has_change = False
            addr_record = defaultdict(lambda: 0)
            for txout in tx.outputs():
                addr_record[txout.address] += 1
            any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)
            for txout in tx.outputs():
                if txout.is_mine and len(tx.outputs()) > 1 \
                        and not has_change:
                    # prioritise hiding outputs on the 'change' branch from user
                    # because no more than one change address allowed
                    if txout.is_change == any_output_on_change_branch and addr_record[txout.address] == 1:
                        my_pubkey, changePath = self.find_my_pubkey_in_txinout(txout)
                        assert changePath
                        changePath = convert_bip32_intpath_to_strpath(changePath)[2:]
                        has_change = True
                    else:
                        output = txout.address
                else:
                    output = txout.address

        self.handler.show_message(_("Confirm Transaction on your Ledger device..."))
        try:
            # Get trusted inputs from the original transactions
            for utxo in inputs:
                sequence = int_to_hex(utxo[5], 4)
                if segwitTransaction and not client_electrum.supports_segwit_trustedInputs():
                    tmp = bfh(utxo[3])[::-1]
                    tmp += bfh(int_to_hex(utxo[1], 4))
                    tmp += bfh(int_to_hex(utxo[6], 8))  # txin['value']
                    chipInputs.append({'value' : tmp, 'witness' : True, 'sequence' : sequence})
                    redeemScripts.append(bfh(utxo[2]))
                elif (not p2shTransaction) or client_electrum.supports_multi_output():
                    txtmp = bitcoinTransaction(bfh(utxo[0]))
                    trustedInput = client_ledger.getTrustedInput(txtmp, utxo[1])
                    trustedInput['sequence'] = sequence
                    if segwitTransaction:
                        trustedInput['witness'] = True
                    chipInputs.append(trustedInput)
                    if p2shTransaction or segwitTransaction:
                        redeemScripts.append(bfh(utxo[2]))
                    else:
                        redeemScripts.append(txtmp.outputs[utxo[1]].script)
                else:
                    tmp = bfh(utxo[3])[::-1]
                    tmp += bfh(int_to_hex(utxo[1], 4))
                    chipInputs.append({'value' : tmp, 'sequence' : sequence})
                    redeemScripts.append(bfh(utxo[2]))

            if opsenderTransaction:
                # Send all inputs
                inputIndex = 0
                rawTx = tx.serialize_to_network()
                client_ledger.enableAlternate2fa(False)
                client_ledger.startUntrustedTransaction(True, inputIndex, chipInputs, redeemScripts[inputIndex],
                                                        version=tx.version, qtumOpSender=True)

                # Send all outputs
                outputData = client_ledger.finalizeInput(b'', 0, 0, changePath, bfh(rawTx))
                outputData['outputData'] = txOutput
                if outputData['confirmationNeeded']:
                    outputData['address'] = output
                    self.handler.finished()
                    pin = self.handler.get_auth(outputData)  # does the authenticate dialog and returns pin
                    if not pin:
                        raise UserWarning()
                    self.handler.show_message(_("Confirmed. Signing Transaction Output..."))

                # Sign the op_sender output
                for i, txout in enumerate(tx.outputs()):
                    decoded = decode_opsender_script(txout.scriptpubkey)
                    if (decoded is not None) and (not decoded[3][1]):
                        sender_pubkey = txout.opsender_pubkey.hex()
                        sender_path = list(self.get_pubkey_derivation(txout.opsender_pubkey, txout))
                        sender_path = self.get_derivation_prefix()[2:] + '/' + convert_bip32_intpath_to_strpath(
                            sender_path)[2:]
                        if not sender_path:
                            self.give_error("No matching pubkey for sign_transaction_sender")  # should never happen
                        outputSignature = client_ledger.untrustedHashSign(sender_path, pin, lockTime=tx.locktime)
                        sig = bfh(push_data((outputSignature + b'\x01').hex()))
                        sig += bfh(push_data(sender_pubkey))
                        sig = bfh(int_to_hex(len(sig))) + sig
                        script = update_opsender_sig(txout.scriptpubkey, sig)
                        tx._outputs[i].scriptpubkey = script
                self.handler.finished()

                # update txOutput
                txOutput = var_int(len(tx.outputs()))
                for o in tx.outputs():
                    txOutput += int_to_hex(o.value, 8)
                    script = o.scriptpubkey.hex()
                    txOutput += var_int(len(script) // 2)
                    txOutput += script
                txOutput = bfh(txOutput)


            # Sign all inputs
            firstTransaction = True
            inputIndex = 0
            rawTx = tx.serialize_to_network()
            client_ledger.enableAlternate2fa(False)
            if segwitTransaction:
                client_ledger.startUntrustedTransaction(True, inputIndex,
                                                            chipInputs, redeemScripts[inputIndex], version=tx.version)
                # we don't set meaningful outputAddress, amount and fees
                # as we only care about the alternateEncoding==True branch
                outputData = client_ledger.finalizeInput(b'', 0, 0, changePath, bfh(rawTx))
                outputData['outputData'] = txOutput
                if outputData['confirmationNeeded']:
                    outputData['address'] = output
                    self.handler.finished()
                    # do the authenticate dialog and get pin:
                    pin = self.handler.get_auth(outputData, client=client_electrum)
                    if not pin:
                        raise UserWarning()
                    self.handler.show_message(_("Confirmed. Signing Transaction..."))
                while inputIndex < len(inputs):
                    singleInput = [ chipInputs[inputIndex] ]
                    client_ledger.startUntrustedTransaction(False, 0,
                                                            singleInput, redeemScripts[inputIndex], version=tx.version)
                    inputSignature = client_ledger.untrustedHashSign(inputsPaths[inputIndex], pin, lockTime=tx.locktime)
                    inputSignature[0] = 0x30 # force for 1.4.9+
                    my_pubkey = inputs[inputIndex][4]
                    tx.add_signature_to_txin(txin_idx=inputIndex,
                                             signing_pubkey=my_pubkey.hex(),
                                             sig=inputSignature.hex())
                    inputIndex = inputIndex + 1
            else:
                while inputIndex < len(inputs):
                    client_ledger.startUntrustedTransaction(firstTransaction, inputIndex,
                                                                chipInputs, redeemScripts[inputIndex], version=tx.version)
                    # we don't set meaningful outputAddress, amount and fees
                    # as we only care about the alternateEncoding==True branch
                    outputData = client_ledger.finalizeInput(b'', 0, 0, changePath, bfh(rawTx))
                    outputData['outputData'] = txOutput
                    if outputData['confirmationNeeded']:
                        outputData['address'] = output
                        self.handler.finished()
                        # do the authenticate dialog and get pin:
                        pin = self.handler.get_auth(outputData, client=client_electrum)
                        if not pin:
                            raise UserWarning()
                        self.handler.show_message(_("Confirmed. Signing Transaction..."))
                    else:
                        # Sign input with the provided PIN
                        inputSignature = client_ledger.untrustedHashSign(inputsPaths[inputIndex], pin, lockTime=tx.locktime)
                        inputSignature[0] = 0x30 # force for 1.4.9+
                        my_pubkey = inputs[inputIndex][4]
                        tx.add_signature_to_txin(txin_idx=inputIndex,
                                                 signing_pubkey=my_pubkey.hex(),
                                                 sig=inputSignature.hex())
                        inputIndex = inputIndex + 1
                    firstTransaction = False
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return
        except BTChipException as e:
            if e.sw in (0x6985, ):  # cancelled by user
                return
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            else:
                self.logger.exception('')
                self.give_error(f'Sign failed {e}', True)
        except BaseException as e:
            self.logger.exception('')
            self.give_error(e, True)
        finally:
            self.handler.finished()

    @runs_in_hwd_thread
    @test_pin_unlocked
    @set_and_unset_signing
    def show_address(self, sequence, txin_type):
        client = self.get_client()
        address_path = self.get_derivation_prefix()[2:] + "/%d/%d"%sequence
        self.handler.show_message(_("Showing address ..."))
        segwit = is_segwit_script_type(txin_type)
        segwitNative = txin_type == 'p2wpkh'
        try:
            client.getWalletPublicKey(address_path, showOnScreen=True, segwit=segwit, segwitNative=segwitNative)
        except BTChipException as e:
            if e.sw == 0x6985:  # cancelled by user
                pass
            elif e.sw == 0x6982:
                raise  # pin lock. decorator will catch it
            elif e.sw == 0x6b00:  # hw.1 raises this
                self.handler.show_error('{}\n{}\n{}'.format(
                    _('Error showing address') + ':',
                    e,
                    _('Your device might not have support for this functionality.')))
            else:
                self.logger.exception('')
                self.handler.show_error(e)
        except BaseException as e:
            self.logger.exception('')
            self.handler.show_error(e)
        finally:
            self.handler.finished()

class LedgerPlugin(HW_PluginBase):
    keystore_class = Ledger_KeyStore
    minimum_library = (0, 1, 30)
    client = None
    DEVICE_IDS = [(0x2581, 0x1807),  # HW.1 legacy btchip
                  (0x2581, 0x2b7c),  # HW.1 transitional production
                  (0x2581, 0x3b7c),  # HW.1 ledger production
                  (0x2581, 0x4b7c),  # HW.1 ledger test
                  (0x2c97, 0x0000),  # Blue
                  (0x2c97, 0x0001),  # Nano-S
                  (0x2c97, 0x0004),  # Nano-X
                  (0x2c97, 0x0005),  # Nano-S Plus
                  (0x2c97, 0x0006),  # Stax
                  (0x2c97, 0x0007),  # RFU
                  (0x2c97, 0x0008),  # RFU
                  (0x2c97, 0x0009),  # RFU
                  (0x2c97, 0x000a)]  # RFU
    VENDOR_IDS = (0x2c97, )
    LEDGER_MODEL_IDS = {
        0x10: "Ledger Nano S",
        0x40: "Ledger Nano X",
        0x50: "Ledger Nano S Plus",
        0x60: "Ledger Stax",
    }
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')

    def __init__(self, parent, config, name):
        self.segwit = config.get("segwit")
        HW_PluginBase.__init__(self, parent, config, name)
        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return
        # to support legacy devices and legacy firmwares
        self.device_manager().register_devices(self.DEVICE_IDS, plugin=self)
        # to support modern firmware
        self.device_manager().register_vendor_ids(self.VENDOR_IDS, plugin=self)

    def get_library_version(self):
        try:
            import btchip
            version = btchip.__version__
        except ImportError:
            raise
        except:
            version = "unknown"
        if BTCHIP:
            return version
        else:
            raise LibraryFoundButUnusable(library_version=version)

    @classmethod
    def _recognize_device(cls, product_key) -> Tuple[bool, Optional[str]]:
        """Returns (can_recognize, model_name) tuple."""
        # legacy product_keys
        if product_key in cls.DEVICE_IDS:
            if product_key[0] == 0x2581:
                return True, "Ledger HW.1"
            if product_key == (0x2c97, 0x0000):
                return True, "Ledger Blue"
            if product_key == (0x2c97, 0x0001):
                return True, "Ledger Nano S"
            if product_key == (0x2c97, 0x0004):
                return True, "Ledger Nano X"
            return True, None
        # modern product_keys
        if product_key[0] == 0x2c97:
            product_id = product_key[1]
            model_id = product_id >> 8
            if model_id in cls.LEDGER_MODEL_IDS:
                model_name = cls.LEDGER_MODEL_IDS[model_id]
                return True, model_name
        # give up
        return False, None

    def can_recognize_device(self, device: Device) -> bool:
        return self._recognize_device(device.product_key)[0]

    @classmethod
    def device_name_from_product_key(cls, product_key) -> Optional[str]:
        return cls._recognize_device(product_key)[1]

    def create_device_from_hid_enumeration(self, d, *, product_key):
        device = super().create_device_from_hid_enumeration(d, product_key=product_key)
        if not self.can_recognize_device(device):
            return None
        return device

    @runs_in_hwd_thread
    def get_btchip_device(self, device):
        ledger = False
        if device.product_key[0] == 0x2581 and device.product_key[1] == 0x3b7c:
            ledger = True
        if device.product_key[0] == 0x2581 and device.product_key[1] == 0x4b7c:
            ledger = True
        if device.product_key[0] == 0x2c97:
            if device.interface_number == 0 or device.usage_page == 0xffa0:
                ledger = True
            else:
                return None  # non-compatible interface of a Nano S or Blue
        if (os.getenv("LEDGER_PROXY_ADDRESS") is not None) and (os.getenv("LEDGER_PROXY_PORT") is not None):
            return DongleServer(os.getenv("LEDGER_PROXY_ADDRESS"), int(os.getenv("LEDGER_PROXY_PORT")), BTCHIP_DEBUG)
        dev = hid.device()
        dev.open_path(device.path)
        dev.set_nonblocking(True)
        return HIDDongleHIDAPI(dev, ledger, BTCHIP_DEBUG)

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        if handler:
            self.handler = handler

        client = self.get_btchip_device(device)
        if client is not None:
            client = Ledger_Client(client, product_key=device.product_key, plugin=self)
        return client

    def setup_device(self, device_info, wizard, purpose):
        device_id = device_info.device.id_
        client = self.scan_and_create_client_for_device(device_id=device_id, wizard=wizard)
        wizard.run_task_without_blocking_gui(
            task=lambda: client.get_xpub(f"m/44'/{constants.net.BIP44_COIN_TYPE}'/0'", 'standard'))  # TODO replace by direct derivation once Nano S > 1.1
        return client

    def get_xpub(self, device_id, derivation, xtype, wizard):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not supported with {}.').format(self.device))
        client = self.scan_and_create_client_for_device(device_id=device_id, wizard=wizard)
        client.checkDevice()
        xpub = client.get_xpub(derivation, xtype)
        return xpub

    @runs_in_hwd_thread
    def get_client(self, keystore, force_pair=True, *,
                   devices=None, allow_user_interaction=True):
        # All client interaction should not be in the main GUI thread
        client = super().get_client(keystore, force_pair,
                                    devices=devices,
                                    allow_user_interaction=allow_user_interaction)
        # returns the client for a given keystore. can use xpub
        #if client:
        #    client.used()
        if client is not None:
            client.checkDevice()
        return client

    @runs_in_hwd_thread
    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        if type(wallet) is not Standard_Wallet:
            keystore.handler.show_error(_('This function is only available for standard wallets when using {}.').format(self.device))
            return
        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)
        keystore.show_address(sequence, txin_type)
