# -*- coding: utf-8 -*-
import os
import timeit
from functools import partial
import unittest
from unittest import TestCase

import saltchannel.saltlib

from saltchannel.saltlib.saltlib_base import SaltLibBase
from saltchannel.saltlib.saltlib_native import SaltLibNative
from saltchannel.saltlib.saltlib_pynacl import SaltLibPyNaCl
from saltchannel.saltlib.saltlib_tweetnaclext import SaltLibTweetNaClExt
from saltchannel.saltlib.saltlib import SaltLib, LibType, RngType

from saltchannel.util.crypto_test_data import CryptoTestData

class BaseTest(TestCase):
    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass


class TestSaltLib(BaseTest):
   
    naclapi_map = {
        '1. SaltLibNative': SaltLibNative(),
        '2. SaltLibPyNaCl': SaltLibPyNaCl(),
        '3. SaltLibTweetNaClExt': SaltLibTweetNaClExt(),
        # '4. SaltLibPure': SaltLibPure(),
    }

    def test_nacl_api_available(self):
        for (name, api) in self.naclapi_map.items():
            with self.subTest(name=name):
                self.assertTrue(api.isAvailable())

    def test_crypto_hash_emptymsg(self):
        for (name, api) in self.naclapi_map.items():
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
        for (name, api) in self.naclapi_map.items():
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
        seed = CryptoTestData.aSig.sec[0:SaltLibBase.crypto_sign_SEEDBYTES]
        for (name, api) in self.naclapi_map.items():
            with self.subTest(name=name):
                (pk, sk) = api.crypto_sign_keypair_not_random(seed)
                self.assertEqual(CryptoTestData.aSig.pub, pk)
                self.assertEqual(CryptoTestData.aSig.sec, sk)

    def test_crypto_box_keypair_not_random(self):
        sk1 = CryptoTestData.aEnc.sec
        sk2 = CryptoTestData.bEnc.sec
        for (name, api) in self.naclapi_map.items():
            with self.subTest(name=name):
                (pk1, sk1) = api.crypto_box_keypair_not_random(sk1)
                self.assertEqual(CryptoTestData.aEnc.pub, pk1)
                self.assertEqual(CryptoTestData.aEnc.sec, sk1)
                (pk2, sk2) = api.crypto_box_keypair_not_random(sk2)
                self.assertEqual(CryptoTestData.bEnc.pub, pk2)
                self.assertEqual(CryptoTestData.bEnc.sec, sk2)

    def test_crypto_sign(self):
        m = bytes([3, 3, 3, 3])
        sk = CryptoTestData.aSig.sec
        pk = CryptoTestData.aSig.pub
        for (name, api) in self.naclapi_map.items():
            with self.subTest(name=name):
                sm = api.crypto_sign(m, sk)
                m2 = api.crypto_sign_open(sm, pk)
                self.assertEqual(m, m2[:len(m)])

                # break the signature
                badsm = bytes([1]) + bytearray(sm[1:])
                with self.assertRaises(saltchannel.saltlib.BadSignatureException) as cm:
                    api.crypto_sign_open(badsm, pk)

    def test_crypto_box_beforenm(self):
        ask = CryptoTestData.aEnc.sec
        apk = CryptoTestData.aEnc.pub
        bsk = CryptoTestData.bEnc.sec
        bpk = CryptoTestData.bEnc.pub
        for (name, api) in self.naclapi_map.items():
            with self.subTest(name=name):
                k1 = api.crypto_box_beforenm(bpk, ask)
                k2 = api.crypto_box_beforenm(apk, bsk)
                self.assertEqual(k1, k2)

    def test_crypto_box(self):
        ask = CryptoTestData.aEnc.sec
        apk = CryptoTestData.aEnc.pub
        bsk = CryptoTestData.bEnc.sec
        bpk = CryptoTestData.bEnc.pub
        m = b'abcdEFGH'
        n = os.urandom(SaltLibBase.crypto_box_NONCEBYTES)
        for (name, api) in self.naclapi_map.items():
            with self.subTest(name=name):
                k1 = api.crypto_box_beforenm(bpk, ask)
                k2 = api.crypto_box_beforenm(apk, bsk)
                c = api.crypto_box_afternm(m, n, k1)
                m2 = api.crypto_box_open_afternm(c, n, k2)
                self.assertEqual(len(m), len(m2))
                self.assertEqual(m, m2)

                # break ciphertext
                _c2 = bytearray(c)
                _c2[-1] = ~_c2[-1] & 0xff
                c2 = bytes(_c2)
                with self.assertRaises(saltchannel.saltlib.BadEncryptedDataException) as cm:
                    m3 = api.crypto_box_open_afternm(c2, n, k2)

    def test_urandom(self):
        for t in LibType:
            SaltLib(lib_type=t, rand_type=RngType.RNG_URANDOM)
            bytes1 = SaltLib.random_bytes(128)
            bytes2 = SaltLib.random_bytes(128)
            self.assertEqual(len(bytes1), len(bytes2))
            self.assertNotEqual(bytes1, bytes2)

            SaltLib(lib_type=t, rand_type=RngType.RNG_IMPL)
            bytes1 = SaltLib.random_bytes(128)
            bytes2 = SaltLib.random_bytes(128)
            self.assertEqual(len(bytes1), len(bytes2))
            self.assertNotEqual(bytes1, bytes2)

    def test_create_sig_keys_from_sec(self):
        for t in LibType:
            for rng in RngType:
                with self.subTest(name=" ".join([str(t), str(rng)])):
                    lib = SaltLib(lib_type=t, rand_type=rng)
                    sig = lib.create_sig_keys_from_sec(CryptoTestData.aSig.sec)
                    self.assertEqual(CryptoTestData.aSig.sec, sig.sec)
                    self.assertEqual(CryptoTestData.aSig.pub, sig.pub)

    def test_create_enc_keys_from_sec(self):
        for t in LibType:
            for rng in RngType:
                with self.subTest(name=" ".join([str(t), str(rng)])):
                    lib = SaltLib(lib_type=t, rand_type=rng)
                    enc = lib.create_enc_keys_from_sec(CryptoTestData.aEnc.sec)
                    self.assertEqual(CryptoTestData.aEnc.sec, enc.sec)
                    self.assertEqual(CryptoTestData.aEnc.pub, enc.pub)

    def test_sign(self):
        for t in LibType:
            for rng in RngType:
                with self.subTest(name=" ".join([str(t), str(rng)])):
                    lib = SaltLib(lib_type=t, rand_type=rng)
                    data1 = bytes([1, 2, 3])
                    signed = lib.sign(data1, CryptoTestData.aSig.sec)
                    data2 = lib.sign_open(signed, CryptoTestData.aSig.pub)
                    self.assertEqual(data1, data2)

    def test_encrypt_decrypt(self):
        for t in LibType:
            for rng in RngType:
                with self.subTest(name=" ".join([str(t), str(rng)])):
                    lib = SaltLib(lib_type=t, rand_type=rng)
                    txt = b"hello world"
                    key = os.urandom(lib.api.crypto_box_SHAREDKEYBYTES)
                    nonce = os.urandom(lib.api.crypto_box_NONCEBYTES)
                    encrypted = lib.encrypt(key, nonce, txt)
                    clear = lib.decrypt(key, nonce, encrypted)
                    self.assertEqual(txt, clear)

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
        sk = CryptoTestData.aSig.sec
        pk = CryptoTestData.aSig.pub
        sm = self.api.crypto_sign(m, sk)
        m2 = self.api.crypto_sign_open(sm, pk)

    def body_crypto_box(self):
        ask = CryptoTestData.aEnc.sec
        bpk = CryptoTestData.bEnc.pub
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
        for apiname, api in sorted(self.naclapi_map.items()):
            print("="*79, "\n {}\n".format(api.__class__.__name__), "-"*78, "\n")
            self.set_api(api)
            for mtd in [method for method in dir(self)
                        if callable(getattr(self, method)) and method.__str__().startswith("body_")]:
                self.run_bench_single(getattr(self, mtd))

if __name__ == '__main__':
    unittest.main()