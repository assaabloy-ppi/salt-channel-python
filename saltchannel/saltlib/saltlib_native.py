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

    # ret: pk, sk
    def crypto_sign_keypair_not_random(self, seed):
        if len(seed) != self.crypto_sign_SEEDBYTES:
            raise ValueError("Invalid seed")
        pk = ctypes.create_string_buffer(self.crypto_sign_PUBLICKEYBYTES)
        sk = ctypes.create_string_buffer(self.crypto_sign_SECRETKEYBYTES)
        wrap(sodium.crypto_sign_seed_keypair(pk, sk, seed))
        return pk.raw, sk.raw

    # ret: sm
    def crypto_sign(self, m, sk):
        sm = ctypes.create_string_buffer(len(m) + self.crypto_sign_BYTES)
        smlen = ctypes.c_ulonglong()
        wrap(sodium.crypto_sign(sm, ctypes.byref(smlen), m, ctypes.c_ulonglong(len(m)), sk))
        return sm.raw

    # ret: m
    def crypto_sign_open(self, sm, pk):
        m = ctypes.create_string_buffer(len(sm))
        mlen = ctypes.c_ulonglong()
        res = sodium.crypto_sign_open(m, ctypes.byref(mlen), sm, ctypes.c_ulonglong(len(sm)), pk)
        if res != 0:
            raise BadSignatureException()
        return m.raw[:mlen.value]

    # ret: pk, sk
    def crypto_box_keypair_not_random(self, sk):
        if len(sk) != self.crypto_box_SECRETKEYBYTES:
            raise ValueError("Invalid secret key length")
        pk = ctypes.create_string_buffer(self.crypto_box_PUBLICKEYBYTES)
        wrap(sodium.crypto_scalarmult_base(pk, sk))
        return pk.raw, sk

    # ret: k
    def crypto_box_beforenm(self, pk, sk):
        c = ctypes.create_string_buffer(self.crypto_box_SHAREDKEYBYTES)
        wrap(sodium.crypto_box_beforenm(c, pk, sk))
        return c.raw

    # ret: c
    def crypto_box_afternm(self, m, n, k):
        padded = (b"\x00"*self.crypto_box_ZEROBYTES) + m
        c = ctypes.create_string_buffer(len(padded))
        wrap(sodium.crypto_box_afternm(c, padded, ctypes.c_ulonglong(len(padded)), n, k))
        return c.raw[self.crypto_box_BOXZEROBYTES:]

    # ret: m
    def crypto_box_open_afternm(self, c, n, k):
        padded = (b"\x00"*self.crypto_box_BOXZEROBYTES) + c
        m = ctypes.create_string_buffer(len(padded))
        res = sodium.crypto_box_open_afternm(m, padded, ctypes.c_ulonglong(len(padded)), n, k)
        if (res != 0):
            raise BadEncryptedDataException()
        return m.raw[self.crypto_box_ZEROBYTES:]

    def crypto_hash(self, m):
        if m is None:
            raise ValueError("invalid parameter")
        h = ctypes.create_string_buffer(sodium.crypto_hash_sha512_bytes()).raw
        wrap(sodium.crypto_hash_sha512(h, m, ctypes.c_ulonglong(len(m))))
        return h
