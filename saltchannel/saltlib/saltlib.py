from util.py import Singleton
from saltlib.saltlib_native import SaltLibNative
from saltlib.saltlib_pure import SaltLibPure

class NoSuchLibException(Exception):
    pass

class SaltLib(metaclass=Singleton):
    LIB_TYPE_NATIVE = 1
    LIB_TYPE_PURE = 2
    LIB_TYPE_BEST = 3

    #def __init__(self, lib_type=LIB_TYPE_BEST):
    #    pass

    @staticmethod
    def getLib(lib_type=LIB_TYPE_BEST):
        return SaltLibNative() if SaltLibNative.isAvailable() else SaltLibPure()