import ctypes
import ctypes.util

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase

sodium = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium'))


def wrap(code):
    if code != 0:
        raise ValueError("libsodium returned {}", code)


class SaltLibNative(SaltLibBase, metaclass=Singleton):


    @staticmethod
    def _getSodium():
        return sodium

    @staticmethod
    def isAvailable():
        return False if not sodium._name else True

    def crypto_hash(self, m):
        if m is None:
            raise ValueError("invalid parameter")
        h = ctypes.create_string_buffer(sodium.crypto_hash_sha512_bytes()).raw
        wrap(sodium.crypto_hash_sha512(h, m, ctypes.c_ulonglong(len(m))))
        return h
