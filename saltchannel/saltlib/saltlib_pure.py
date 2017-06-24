from util.py import Singleton
from saltlib.saltlib_base import SaltLibBase

class SaltLibPure(SaltLibBase, metaclass=Singleton):
    zz = 0

    @staticmethod
    def isAvailable():
        import importlib
        tweetnacl = importlib.util.find_spec("tweetnacl")
        return tweetnacl is not None