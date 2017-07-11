# -*- coding: utf-8 -*-

from .pure_pynacl import TypeEnum, integer, Int, IntArray
from .pure_pynacl import tweetnacl
from .pure_pynacl.tweetnacl import u8

from .saltlib_base import SaltLibBase

class SaltLibPure(SaltLibBase):

    @staticmethod
    def isAvailable():
        import importlib.util
        mod = importlib.util.find_spec("saltchannel.saltlib.pure_pynacl.tweetnacl")
        return mod is not None

    # TEST PASSED
    # ret: pk
    def crypto_sign_keypair_not_random(self, seed):
        if len(seed) != self.crypto_sign_SEEDBYTES:
            raise ValueError("Invalid seed")
        pk = IntArray(u8, size=self.crypto_sign_PUBLICKEYBYTES)
        d = IntArray(u8, size=64)
        p = [tweetnacl.gf() for i in range(4)]

        tweetnacl.crypto_hash_sha512_tweet(d, seed, 32)
        d[0] &= 248
        d[31] &= 127
        d[31] |= 64
        tweetnacl.scalarbase(p, d)
        tweetnacl.pack(pk, p)
        return bytes(pk), seed + bytes(pk)

    # TEST PASSED
    # ret: sm
    def crypto_sign(self, m, sk):
        sm = bytearray(len(m) + self.crypto_sign_BYTES)
        smlen = -1
        tweetnacl.crypto_sign_ed25519_tweet(sm, smlen, m, len(m), sk)
        return bytes(sm)

    # TEST PASSED
    # ret: m
    def crypto_sign_open(self, sm, pk):
        m = bytearray(len(sm))
        mlen = -1
        res = tweetnacl.crypto_sign_ed25519_tweet_open(m, mlen, sm, len(sm), pk)
        if res != 0:
            raise BadSignatureException()
        return bytes(m[:len(sm) - self.crypto_sign_BYTES])

    # TEST PASSED
    def crypto_box_keypair_not_random(self, sk):
        if len(sk) != self.crypto_box_SECRETKEYBYTES:
            raise ValueError("Invalid secret key length")
        pk = IntArray(u8, size=self.crypto_box_PUBLICKEYBYTES)
        tweetnacl.crypto_scalarmult_curve25519_tweet_base(pk, sk)
        return bytes(pk), bytes(sk)

    # TEST PASSED
    # ret: k
    def crypto_box_beforenm(self, pk, sk):
        k = IntArray(u8, size=self.crypto_box_SHAREDKEYBYTES)
        tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k, pk, sk)
        return bytes(k)

    # TEST FAILED
    # ret: c
    def crypto_box_afternm(self, m, n, k):
        padded = (b"\x00" * self.crypto_box_ZEROBYTES) + m
        c = IntArray(u8, size=len(padded))
        tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_afternm(c, padded, len(padded), n, k)
        return bytes(c)[self.crypto_box_BOXZEROBYTES:]

    # TEST FAILED
    # ret: m
    def crypto_box_open_afternm(self, c, n, k):
        try:
            padded = (b"\x00" * self.crypto_box_BOXZEROBYTES) + c
            m = IntArray(u8, size=len(padded))
            res = tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(m, padded, len(padded), n, k)
            if res != 0:
                raise BadEncryptedDataException()
            return bytes(m)[self.crypto_box_ZEROBYTES:]
        except Exception as e:
            raise BadEncryptedDataException(e)

    # TEST PASSED
    # ret: h
    def crypto_hash(self, m):
        if m is None:
            raise ValueError("invalid parameter")
        h = IntArray(u8, size=64)
        tweetnacl.crypto_hash_sha512_tweet(h, list(m), len(m))
        return bytes(h)