import nacl.raw as nacl

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase

class SaltLibTweetNaClExt(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def isAvailable():
        return True

    # ret: pk, sk
    def crypto_sign_keypair_not_random(self, seed):
        raise NotImplementedError("Not Implemented")

    def crypto_hash(self, m):
        return nacl.crypto_hash(m)