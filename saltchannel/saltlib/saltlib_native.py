# -*- coding: utf-8 -*-

import ctypes
import ctypes.util

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase
from saltchannel.saltlib.saltlib_base import BadSignatureException
from saltchannel.saltlib.saltlib_base import BadEncryptedDataException

sodium = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium'))

def wrap(code):
    if code != 0:
        raise ValueError("libsodium returned ", code)


class SaltLibNative(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def _getSodium():
        return sodium

    @staticmethod
    def isAvailable():
        return False if not sodium._name else True

    def crypto_sign_keypair_not_random(self, seed):
        """
        The crypto_sign_keypair_not_random function takes a seed bytearray and
        deterministically generates corresponding public and secret key tuple.

        Args:
            seed (bytes): Seed bytearray of lenghth crypto_sign_SEEDBYTES

        Returns:
            (pk: bytes, sk: bytes): Public and secret keys as a tuple
        """
        if len(seed) != self.crypto_sign_SEEDBYTES:
            raise ValueError("Invalid seed")
        pk = ctypes.create_string_buffer(self.crypto_sign_PUBLICKEYBYTES)
        sk = ctypes.create_string_buffer(self.crypto_sign_SECRETKEYBYTES)
        wrap(sodium.crypto_sign_seed_keypair(pk, sk, seed))
        return pk.raw, sk.raw

    def crypto_sign(self, m, sk):
        """
        The crypto_sign function signs a message m using the signer's secret
        key sk.

        Args:
            m (bytes): message to sign
            sk (bytes): secret key

        Returns:
            bytes: signed message
        """
        sm = ctypes.create_string_buffer(len(m) + self.crypto_sign_BYTES)
        smlen = ctypes.c_ulonglong()
        wrap(sodium.crypto_sign(sm, ctypes.byref(smlen), m, ctypes.c_ulonglong(len(m)), sk))
        return sm.raw

    def crypto_sign_open(self, sm, pk):
        """
        The crypto_sign_open function verifies the signature in sm using the signer's public key pk.

        Args:
            sm (bytes): signed message
            pk (bytes): public key

        Returns:
            bytes: original message
        Raises:
            BadSignatureException:
        """
        m = ctypes.create_string_buffer(len(sm))
        mlen = ctypes.c_ulonglong()
        res = sodium.crypto_sign_open(m, ctypes.byref(mlen), sm, ctypes.c_ulonglong(len(sm)), pk)
        if res != 0:
            raise BadSignatureException()
        return m.raw[:mlen.value]

    def crypto_box_keypair_not_random(self, sk):
        """
        The crypto_box_keypair_not_random function takes a secret key and generates
        a corresponding public key deterministically.

        Args:
            sk (bytes): secret key

        Returns:
            (pk: bytes, sk: bytes): Public and secret keys as a tuple
        """
        if len(sk) != self.crypto_box_SECRETKEYBYTES:
            raise ValueError("Invalid secret key length")
        pk = ctypes.create_string_buffer(self.crypto_box_PUBLICKEYBYTES)
        wrap(sodium.crypto_scalarmult_base(pk, sk))
        return pk.raw, sk

    def crypto_box_beforenm(self, pk, sk):
        """
        The first step of crypto_box; the x25519 key agreement. This function generates the
        shared secret key based on peer's public key and caller's secret key.

        Args:
            pk (bytes): public key
            sk (bytes): secret key

        Returns:
            bytes: shared key

        """
        k = ctypes.create_string_buffer(self.crypto_box_SHAREDKEYBYTES)
        wrap(sodium.crypto_box_beforenm(k, pk, sk))
        return k.raw

    def crypto_box_afternm(self, m, n, k):
        """
        The crypto_box_afternm function encrypts and authenticates a
        message m using the shared key k and a nonce n.
        Note: no padding required (in contrast to original NaCl API)

        Args:
            m (bytes): message
            n (bytes): nonce of length crypto_box_NONCEBYTES
            k (bytes): shared key

        Returns:
            bytes: ciphertext (encrypted and signed message)
        """
        padded = (b"\x00"*self.crypto_box_ZEROBYTES) + m
        c = ctypes.create_string_buffer(len(padded))
        wrap(sodium.crypto_box_afternm(c, padded, ctypes.c_ulonglong(len(padded)), n, k))
        return c.raw[self.crypto_box_BOXZEROBYTES:]

    def crypto_box_open_afternm(self, c, n, k):
        """
        The crypto_box_open function verifies and decrypts a ciphertext c using the shared key k
        and a nonce n. If the ciphertext fails verification, this function throws BadEncryptedData.
        Note: no padding required (in contrast to original NaCl API)

        Args:
            c (bytes): ciphertext
            n (bytes): nonce of length crypto_box_NONCEBYTES
            k (bytes): shared key

        Returns:
            bytes: decrypted message
        Raises:
            BadEncryptedDataException:
        """
        padded = (b"\x00"*self.crypto_box_BOXZEROBYTES) + c
        m = ctypes.create_string_buffer(len(padded))
        res = sodium.crypto_box_open_afternm(m, padded, ctypes.c_ulonglong(len(padded)), n, k)
        if (res != 0):
            raise BadEncryptedDataException()
        return m.raw[self.crypto_box_ZEROBYTES:]

    def crypto_hash(self, m):
        """
        The crypto_hash function hashes a message m using SHA-512.

        Args:
            m (bytes): message

        Returns:
            bytes: hashed data
        """
        if m is None:
            raise ValueError("invalid parameter")
        h = ctypes.create_string_buffer(sodium.crypto_hash_sha512_bytes()).raw
        wrap(sodium.crypto_hash_sha512(h, m, ctypes.c_ulonglong(len(m))))
        return h
