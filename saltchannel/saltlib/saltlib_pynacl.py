# -*- coding: utf-8 -*-

from nacl import bindings

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure

from .exceptions import BadEncryptedDataException, BadSignatureException
from .saltlib_base import SaltLibBase

class SaltLibPyNaCl(SaltLibBase):

    @staticmethod
    def isAvailable():
        return True

    # ret: pk, sk
    def crypto_sign_keypair_not_random(self, seed):
        if len(seed) != self.crypto_sign_SEEDBYTES:
            raise ValueError("Invalid seed")
        pk = ffi.new("unsigned char[]", self.crypto_sign_PUBLICKEYBYTES)
        sk = ffi.new("unsigned char[]", self.crypto_sign_SECRETKEYBYTES)
        rc = lib.crypto_sign_seed_keypair(pk, sk, seed)
        ensure(rc == 0,
               'Unexpected library error',
               raising=exc.RuntimeError)
        return (ffi.buffer(pk, self.crypto_sign_PUBLICKEYBYTES)[:],
                ffi.buffer(sk, self.crypto_sign_SECRETKEYBYTES)[:],
                )

    # ret: sm
    def crypto_sign(self, m, sk):
        return bindings.crypto_sign(m, sk)

    # ret: m
    def crypto_sign_open(self, sm, pk):
        try:
            return bindings.crypto_sign_open(sm, pk)
        except Exception as e:
            raise BadSignatureException(e)

    # ret: k
    def crypto_box_beforenm(self, pk, sk):
        return bindings.crypto_box_beforenm(pk, sk)

    # ret: c
    def crypto_box_afternm(self, m, n, k):
        return bindings.crypto_box_afternm(m, n, k)

    # ret: m
    def crypto_box_open_afternm(self, c, n, k):
        try:
            return bindings.crypto_box_open_afternm(c, n, k)
        except Exception as e:
            raise BadEncryptedDataException(e)

    # ret: pk, sk
    def crypto_box_keypair_not_random(self, sk):
        if len(sk) != self.crypto_box_SECRETKEYBYTES:
            raise ValueError("Invalid secret key length")
        return bindings.crypto_scalarmult_base(sk), sk

    # ret: h
    def crypto_hash(self, m):
        return bindings.crypto_hash(m)