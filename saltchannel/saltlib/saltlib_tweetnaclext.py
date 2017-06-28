import nacl.raw as nacl

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase

class SaltLibTweetNaClExt(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def isAvailable():
        return True

    def crypto_hash(self, m):
        return nacl.crypto_hash(m)