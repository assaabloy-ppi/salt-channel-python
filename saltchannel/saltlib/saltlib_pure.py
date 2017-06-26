from saltchannel.saltlib.pure_pynacl import TypeEnum, integer, Int, IntArray
from saltlib.pure_pynacl import tweetnacl
from saltlib.pure_pynacl.tweetnacl import u8

from util.py import Singleton
from saltlib.saltlib_base import SaltLibBase

class SaltLibPure(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def isAvailable():
        import importlib.util
        mod = importlib.util.find_spec("saltlib.pure_pynacl.tweetnacl")
        return mod is not None

    def crypto_hash(self, m):
        if m is None:
            raise ValueError("invalid parameter")
        h = IntArray(u8, size=64)
        tweetnacl.crypto_hash_sha512_tweet(h, [ord(c) for c in m], len(m))
        return bytes(h)