from saltchannel.saltlib.pure_pynacl import TypeEnum, integer, Int, IntArray
from saltchannel.saltlib.pure_pynacl import tweetnacl
from saltchannel.saltlib.pure_pynacl.tweetnacl import u8

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase

class SaltLibPure(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def isAvailable():
        import importlib.util
        mod = importlib.util.find_spec("saltchannel.saltlib.pure_pynacl.tweetnacl")
        return mod is not None

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


    def crypto_hash(self, m):
        if m is None:
            raise ValueError("invalid parameter")
        h = IntArray(u8, size=64)
        tweetnacl.crypto_hash_sha512_tweet(h, list(m), len(m))
        return bytes(h)