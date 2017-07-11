# -*- coding: utf-8 -*-

from saltchannel.util import Singleton
from .saltlib_native import SaltLibNative
from .saltlib_pynacl import SaltLibPyNaCl
from .saltlib_tweetnaclext import SaltLibTweetNaClExt



class SaltLib(metaclass=Singleton):
    LIB_TYPE_BEST = 0
    LIB_TYPE_NATIVE = 1
    LIB_TYPE_PYNACL = 2
    LIB_TYPE_TWEETNACL_EXT = 3
    LIB_TYPE_PURE = 4

    lib_map = {
        LIB_TYPE_NATIVE: SaltLibNative(),
        LIB_TYPE_PYNACL: SaltLibPyNaCl(),
        LIB_TYPE_TWEETNACL_EXT: SaltLibTweetNaClExt(),
        #LIB_TYPE_PURE: SaltLibPure(),
    }

    @staticmethod
    def getLib(lib_type=LIB_TYPE_BEST):
        if lib_type == SaltLib.LIB_TYPE_BEST:
            for t, api in sorted(SaltLib.lib_map.items()):
                if api.isAvailable():
                    return api
                else:
                    raise NoSuchLibException
            else:
                return SaltLib.lib_map[lib_type]