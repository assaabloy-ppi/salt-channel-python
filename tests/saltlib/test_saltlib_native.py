from unittest import TestCase
from saltchannel.saltlib.saltlib_native import SaltLibNative
from saltchannel.saltlib.saltlib_pure import SaltLibPure


class BaseTest(TestCase):
    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        #self.target = SaltLibNative()
        self.target = SaltLibPure()
        self.assertTrue(self.target.isAvailable())
        pass

    def tearDown(self):
        pass


class TestSaltLibNative(BaseTest):

    def test_crypto_hash_emptymsg(self):
        self.assertEqual(self.target.crypto_hash(''),
                         bytes([
                             0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                             0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                             0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                             0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                             0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                             0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                             0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                             0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
                         ]))

    def test_crypto_hash_abc(self):
        self.assertEqual(self.target.crypto_hash('abc'),
                         bytes([
                             0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
                             0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
                             0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
                             0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
                             0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
                             0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
                             0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                             0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
                         ]))