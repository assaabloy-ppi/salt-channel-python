# -*- coding: utf-8 -*-

import unittest
from unittest import TestCase

from saltchannel.exceptions import BadPeer
from saltchannel.a1a2.packets import *
from saltchannel.util.crypto_test_data import CryptoTestData

class BaseTest(TestCase):
    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass


class TestA1(BaseTest):

    def test_A1_prop_valid(self):
        a1 = A1Packet()
        a1c = A1Packet()

        a1c.from_bytes(src=bytes(a1))
        self.assertEqual(bytes(a1), bytes(a1c))

        a1.data.AddressType = A1Packet.ADDRESS_TYPE_PUBKEY
        a1.data.AddressSize = 32
        a1.create_opt_fields()
        a1.Address = CryptoTestData.aSig.pub

        a1c.from_bytes(src=bytes(a1))
        self.assertEqual(bytes(a1), bytes(a1c))
        self.assertEqual(a1c.Address, CryptoTestData.aSig.pub)

    def test_A1_prop_invalid(self):
        a1 = A1Packet()

        a1.data.AddressType = A1Packet.ADDRESS_TYPE_ANY
        a1.data.AddressSize = 1
        with self.assertRaises(BadPeer) as cm:
            a1c = A1Packet()
            a1c.from_bytes(src=bytes(a1))

        a1.data.AddressType = A1Packet.ADDRESS_TYPE_PUBKEY
        a1.data.AddressSize = 32
        a1.Address = b'123'
        with self.assertRaises(BadPeer) as cm:
            a1c = A1Packet()
            a1c.from_bytes(src=bytes(a1))

        a1.data.AddressType = A1Packet.ADDRESS_TYPE_PUBKEY + 1
        a1.data.AddressSize = 32
        a1.Address = CryptoTestData.aSig.pub
        with self.assertRaises(BadPeer) as cm:
            a1c = A1Packet()
            a1c.from_bytes(src=bytes(a1))


class TestA2(BaseTest):

    def test_A2_prop_nosuchserver(self):
        a2 = A2Packet(no_such_server=True)
        a2c = A2Packet()

        a2c.from_bytes(src=bytes(a2))
        self.assertEqual(bytes(a2), bytes(a2c))
        self.assertEqual(a2c.data.Header.NoSuchServer, 1)
        self.assertEqual(a2c.data.Header.LastFlag, 1)
        self.assertEqual(a2c.data.Count, 0)
        self.assertFalse(a2c.opt.Prot)
        self.assertFalse(a2c.Prot)    # shortcut

    def test_A2_prop_valid1(self):
        a2 = A2Packet()
        a2c = A2Packet()

        a2c.from_bytes(src=bytes(a2))
        self.assertEqual(bytes(a2), bytes(a2c))
        self.assertEqual(a2c.data.Header.NoSuchServer, 0)
        self.assertEqual(a2c.data.Header.LastFlag, 1)
        self.assertEqual(a2c.data.Count, 0)
        self.assertFalse(a2c.opt.Prot)
        self.assertFalse(a2c.Prot)    # shortcut

    def test_A2_prop_valid2(self):
        a2 = A2Packet()
        a2c = A2Packet()

        a2.data.Count = 1
        a2.create_opt_fields(prot_count=1)
        a2.Prot[0].P1 = util.cbytes(A2Packet.SC2_PROT_STRING)
        a2.Prot[0].P2 = util.cbytes(A2Packet.UNSPECIFIED_PROT_STRING)

        self.assertEqual(bytes(a2.Prot[0].P1), A2Packet.SC2_PROT_STRING)
        self.assertEqual(bytes(a2.Prot[0].P2), A2Packet.UNSPECIFIED_PROT_STRING)

        a2c.from_bytes(src=bytes(a2))
        self.assertEqual(bytes(a2), bytes(a2c))
        self.assertEqual(a2c.data.Header.NoSuchServer, 0)
        self.assertEqual(a2c.data.Header.LastFlag, 1)
        self.assertEqual(a2c.data.Count, 1)
        self.assertTrue(a2c.opt.Prot)
        self.assertEqual(bytes(a2c.Prot[0].P1), A2Packet.SC2_PROT_STRING)
        self.assertEqual(bytes(a2c.Prot[0].P2), A2Packet.UNSPECIFIED_PROT_STRING)

    def test_A2_prop_valid3(self):
        P1_TEST_VALID = b'A01b_3-de_'   # valid ranges: 'A' - 'Z', 'a' - 'z', '0' - '9', '-', '.', '/', '_'
        P2_TEST_VALID = b'..--//__0x'   # valid ranges: 'A' - 'Z', 'a' - 'z', '0' - '9', '-', '.', '/', '_'
        a2 = A2Packet()
        a2c = A2Packet()

        a2.data.Count = 2
        a2.create_opt_fields(prot_count=2)
        a2.Prot[0].P1 = util.cbytes(A2Packet.SC2_PROT_STRING)
        a2.Prot[0].P2 = util.cbytes(A2Packet.UNSPECIFIED_PROT_STRING)
        a2.Prot[1].P1 = util.cbytes(P1_TEST_VALID)
        a2.Prot[1].P2 = util.cbytes(P2_TEST_VALID)

        self.assertEqual(bytes(a2.Prot[0].P1), A2Packet.SC2_PROT_STRING)
        self.assertEqual(bytes(a2.Prot[0].P2), A2Packet.UNSPECIFIED_PROT_STRING)
        self.assertEqual(bytes(a2.Prot[1].P1), P1_TEST_VALID)
        self.assertEqual(bytes(a2.Prot[1].P2), P2_TEST_VALID)

        a2c.from_bytes(src=bytes(a2))
        self.assertEqual(bytes(a2), bytes(a2c))
        self.assertEqual(a2c.data.Header.NoSuchServer, 0)
        self.assertEqual(a2c.data.Header.LastFlag, 1)
        self.assertEqual(a2c.data.Count, 2)
        self.assertTrue(a2c.opt.Prot)
        self.assertEqual(bytes(a2c.Prot[0].P1), A2Packet.SC2_PROT_STRING)
        self.assertEqual(bytes(a2c.Prot[0].P2), A2Packet.UNSPECIFIED_PROT_STRING)
        self.assertEqual(bytes(a2c.Prot[1].P1), P1_TEST_VALID)
        self.assertEqual(bytes(a2c.Prot[1].P2), P2_TEST_VALID)

    def test_A2_prop_invalid2(self):
        a2 = A2Packet()
        a2c = A2Packet()

        a2.data.Count = 1
        a2.create_opt_fields(prot_count=1)
        a2.Prot[0].P1 = util.cbytes(b':+@)(`#^&*')
        a2.Prot[0].P2 = util.cbytes(b'_ _\t><=~12')
        with self.assertRaises(BadPeer) as cm:
            a2c.from_bytes(src=bytes(a2))



if __name__ == '__main__':
    unittest.main()