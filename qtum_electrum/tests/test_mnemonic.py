import unittest
from lib import keystore
from lib import mnemonic
from lib import old_mnemonic
from lib.util import bh2u

from . import SequentialTestCase


class Test_NewMnemonic(SequentialTestCase):

    def test_to_seed(self):
        seed = mnemonic.Mnemonic.mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEqual(bh2u(seed),
                          '30a7f31981208c55102f15de25c5d9b9cacabec0dbc67eb4bcb18335e311a32cd6cd3f59c712d1671d7d7c88a3799896558aa717aa4fd612488d01313dc1c187')

    def test_random_seeds(self):
        iters = 10
        m = mnemonic.Mnemonic(lang='en')
        for _ in range(iters):
            seed = m.make_seed()
            i = m.mnemonic_decode(seed)
            self.assertEqual(m.mnemonic_encode(i), seed)


class Test_OldMnemonic(SequentialTestCase):

    def test(self):
        seed = '8edad31a95e7d59f8837667510d75a4d'
        result = old_mnemonic.mn_encode(seed)
        words = 'hardly point goal hallway patience key stone difference ready caught listen fact'
        self.assertEqual(result, words.split())
        self.assertEqual(old_mnemonic.mn_decode(result), seed)

class Test_BIP39Checksum(SequentialTestCase):

    def test(self):
        mnemonic = u'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
        is_checksum_valid, is_wordlist_valid = keystore.bip39_is_checksum_valid(mnemonic)
        self.assertTrue(is_wordlist_valid)
        self.assertTrue(is_checksum_valid)
