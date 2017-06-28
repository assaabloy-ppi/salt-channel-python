from nacl import bindings

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase

class SaltLibPyNaCl(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def isAvailable():
        return True

    def crypto_hash(self, m):
        return bindings.crypto_hash(m)