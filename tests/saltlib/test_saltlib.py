import os
import timeit
from functools import partial
import unittest
from unittest import TestCase

from saltchannel.saltlib.saltlib_base import SaltLibBase
from saltchannel.saltlib.saltlib_base import BadSignatureException
from saltchannel.saltlib.saltlib_base import BadEncryptedDataException
from saltchannel.saltlib.saltlib_native import SaltLibNative
from saltchannel.saltlib.saltlib_pynacl import SaltLibPyNaCl
from saltchannel.saltlib.saltlib_pure import SaltLibPure
from saltchannel.saltlib.saltlib_tweetnaclext import SaltLibTweetNaClExt

naclapi_map = {
            '1. SaltLibNative': SaltLibNative(),
            '2. SaltLibPyNaCl': SaltLibPyNaCl(),
            '3. SaltLibTweetNaClExt': SaltLibTweetNaClExt(),
            #'4. SaltLibPure': SaltLibPure(),
        }

class SaltTestData:

    aSigPub = bytes.fromhex('5529ce8ccf68c0b8ac19d437ab0f5b32723782608e93c6264f184ba152c2357b')
    aSigSec = bytes.fromhex('55f4d1d198093c84de9ee9a6299e0f6891c2e1d0b369efb592a9e3f169fb0f79') + aSigPub

    aEncSec = bytes( [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ])

    aEncPub = bytes( [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    ])

    bEncSec = bytes( [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    ])

    bEncPub =  bytes([
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ])

class BaseTest(TestCase):
    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass


class TestSaltLib(BaseTest):

    def test_nacl_api_available(self):
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                self.assertTrue(api.isAvailable())

    def test_crypto_hash_emptymsg(self):
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                self.assertEqual(api.crypto_hash(b''),
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
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                self.assertEqual(api.crypto_hash(b'abc'),
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

    def test_crypto_sign_keypair_not_random(self):
        seed = SaltTestData.aSigSec[0:SaltLibBase.crypto_sign_SEEDBYTES]
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                (pk, sk) = api.crypto_sign_keypair_not_random(seed)
                self.assertEqual(SaltTestData.aSigPub, pk)
                self.assertEqual(SaltTestData.aSigSec, sk)

    def test_crypto_box_keypair_not_random(self):
        sk1 = SaltTestData.aEncSec
        sk2 = SaltTestData.bEncSec
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                (pk1, sk1) = api.crypto_box_keypair_not_random(sk1)
                self.assertEqual(SaltTestData.aEncPub, pk1)
                self.assertEqual(SaltTestData.aEncSec, sk1)
                (pk2, sk2) = api.crypto_box_keypair_not_random(sk2)
                self.assertEqual(SaltTestData.bEncPub, pk2)
                self.assertEqual(SaltTestData.bEncSec, sk2)

    def test_crypto_sign(self):
        m = bytes([3, 3, 3, 3])
        sk = SaltTestData.aSigSec
        pk = SaltTestData.aSigPub
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                sm = api.crypto_sign(m, sk)
                m2 = api.crypto_sign_open(sm, pk)
                self.assertEqual(m, m2[:len(m)])

                # break the signature
                badsm = bytes([1]) + bytearray(sm[1:])
                with self.assertRaises(BadSignatureException) as cm:
                    api.crypto_sign_open(badsm, pk)

    def test_crypto_box_beforenm(self):
        ask = SaltTestData.aEncSec
        apk = SaltTestData.aEncPub
        bsk = SaltTestData.bEncSec
        bpk = SaltTestData.bEncPub
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                k1 = api.crypto_box_beforenm(bpk, ask)
                k2 = api.crypto_box_beforenm(apk, bsk)
                self.assertEqual(k1, k2)

    def test_crypto_box(self):
        ask = SaltTestData.aEncSec
        apk = SaltTestData.aEncPub
        bsk = SaltTestData.bEncSec
        bpk = SaltTestData.bEncPub
        m = b'abcdEFGH'
        n = os.urandom(SaltLibBase.crypto_box_NONCEBYTES)
        #m = /*(b'\x00'*SaltLibBase.crypto_box_BOXZEROBYTES)*/ + message
        #m = message
        for (name, api) in naclapi_map.items():
            with self.subTest(name=name):
                k1 = api.crypto_box_beforenm(bpk, ask)
                k2 = api.crypto_box_beforenm(apk, bsk)
                c = api.crypto_box_afternm(m, n, k1)
                m2 = api.crypto_box_open_afternm(c, n, k2)
                #message2 = m2 #[SaltLibBase.crypto_box_BOXZEROBYTES:]
                self.assertEqual(len(m), len(m2))
                self.assertEqual(m, m2)

                # break ciphertext
                _c2 = bytearray(c)
                _c2[-1] = ~_c2[-1] & 0xff
                c2 = bytes(_c2)
                with self.assertRaises(BadEncryptedDataException) as cm:
                    m3 = api.crypto_box_open_afternm(c2, n, k2)

class BenchSaltLib:

    def __init__(self):
        self.rndmsg = os.urandom(10240)
        self.seed = os.urandom(SaltLibBase.crypto_sign_SEEDBYTES)
        self.nonce = os.urandom(SaltLibBase.crypto_box_NONCEBYTES)
        self.box_sk = os.urandom(SaltLibBase.crypto_box_SECRETKEYBYTES)

    def set_api(self, api):
        self.api = api

    def body_crypto_hash(self):
        self.api.crypto_hash(self.rndmsg)
        pass

    def body_crypto_sign_keypair_not_random(self):
        self.api.crypto_sign_keypair_not_random(self.seed)
        pass

    def body_crypto_sign(self):
        m = self.rndmsg
        sk = SaltTestData.aSigSec
        pk = SaltTestData.aSigPub
        sm = self.api.crypto_sign(m, sk)
        m2 = self.api.crypto_sign_open(sm, pk)

    def body_crypto_box(self):
        ask = SaltTestData.aEncSec;
        bpk = SaltTestData.bEncPub;
        m = b'\0' * SaltLibBase.crypto_box_BOXZEROBYTES + self.rndmsg

        k1 = self.api.crypto_box_beforenm(bpk, ask)
        c = self.api.crypto_box_afternm(m, self.nonce, k1)
        m2 = self.api.crypto_box_open_afternm(c, self.nonce, k1)

    def body_crypto_box_keypair_not_random(self):
        self.api.crypto_box_keypair_not_random(self.box_sk)
        pass


    def body_SYNTHETIC(self):
        self.body_crypto_hash()
        self.body_crypto_sign_keypair_not_random()
        self.body_crypto_sign()
        self.body_crypto_box_keypair_not_random()
        self.body_crypto_box()
        pass

    def run_bench_single(self, f):
        print(" {}() time: {:.3f} ms".format(f.__name__.lstrip("body_"),
                                          1000*min(timeit.Timer(partial(f)).repeat(repeat=33, number=1))))


    def run_bench_suite(self):
        for apiname, api in sorted(naclapi_map.items()):
            print("="*79, "\n {}\n".format(api.__class__.__name__), "-"*78, "\n")
            self.set_api(api)
            for mtd in [method for method in dir(self)
                        if callable(getattr(self, method)) and method.__str__().startswith("body_")]:
                self.run_bench_single(getattr(self, mtd))

if __name__ == '__main__':
    unittest.main()