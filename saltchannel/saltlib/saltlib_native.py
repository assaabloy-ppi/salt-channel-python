import ctypes
import ctypes.util

from util.py import Singleton
from saltlib.saltlib_base import SaltLibBase

sodium = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium'))

class SaltLibNative(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def _getSodium():
        return sodium

    @staticmethod
    def isAvailable():
        return False if not sodium.name else True

