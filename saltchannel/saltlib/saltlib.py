# -*- coding: utf-8 -*-
import os
from enum import Enum

from saltchannel.util import Singleton
from .saltlib_native import SaltLibNative
from .saltlib_pynacl import SaltLibPyNaCl
from .saltlib_tweetnaclext import SaltLibTweetNaClExt
from .exceptions import NoSuchLibException

from ..util.key_pair import KeyPair

class LibType(Enum):
    LIB_TYPE_BEST = 0
    LIB_TYPE_NATIVE = 1
    LIB_TYPE_PYNACL = 2
    LIB_TYPE_TWEETNACL_EXT = 3
    # LIB_TYPE_PURE = 4

class RngType(Enum):
    RNG_URANDOM = 0   # default random generator will just read /dev/urendom
    RNG_IMPL = 1      # implementation specific random generator

class SaltLib(metaclass=Singleton):

    lib_map = {
        LibType.LIB_TYPE_NATIVE.value: SaltLibNative(),
        LibType.LIB_TYPE_PYNACL.value: SaltLibPyNaCl(),
        LibType.LIB_TYPE_TWEETNACL_EXT.value: SaltLibTweetNaClExt(),
        #LibType.LIB_TYPE_PURE: SaltLibPure(),
    }

    def __init__(self, lib_type=LibType.LIB_TYPE_BEST, rand_type=RngType.RNG_URANDOM):
        self.api = SaltLib.getLib(lib_type)
        SaltLib._rand = os.urandom if rand_type == RngType.RNG_URANDOM else self.api.randombytes

    @staticmethod
    def getLib(lib_type=LibType.LIB_TYPE_BEST):
        SaltLib.lib_type = lib_type
        if lib_type == LibType.LIB_TYPE_BEST:
            for t, api in sorted(SaltLib.lib_map.items()):
                if api.isAvailable():
                    return api
                else:
                    raise NoSuchLibException
            else:
                return SaltLib.lib_map[lib_type]

    @staticmethod
    def random_bytes(n):
        return SaltLib._rand(n)

    def create_enc_keys(self):
        self.create_enc_keys_from_sec(self.random_bytes(self.api.crypto_box_SECRETKEYBYTES))

    def create_enc_keys_from_sec(self, sec):
        pk, sk = self.api.crypto_box_keypair_not_random(sec)
        return KeyPair(sec=sk, pub=pk)

    def create_sig_keys(self):
        return self.create_sig_keys_from_sec(self.random_bytes(self.api.crypto_sign_SEEDBYTES))

    def create_sig_keys_from_sec(self, sec):
        pk, sk = self.api.crypto_sign_keypair_not_random(sec[:self.api.crypto_sign_SEEDBYTES])
        return KeyPair(sec=sk, pub=pk)

    def sign(self, msg, sig_sec_key):
        return self.api.crypto_sign(msg, sig_sec_key)

    def sign_open(self, smsg, sig_sec_key):
        return self.api.crypto_sign_open(smsg, sig_sec_key)

    def sha512(self, msg):
        return self.api.crypto_hash(msg)

    def compute_shared_key(self, my_sk, peer_pk):
        if len(my_sk) != self.api.crypto_box_SECRETKEYBYTES:
            raise ValueError("bad length of my_priv: ", len(my_sk))
        if len(peer_pk) != self.api.crypto_box_PUBLICKEYBYTES:
            raise ValueError("bad length of peer_pub: ", len(peer_pk))
        return self.api.crypto_box_beforenm(peer_pk, my_sk)

    def encrypt(self, key, nonce, msg):
        return self.api.crypto_box_afternm(msg, nonce, key)

    def decrypt(self, key, nonce, encrypted):
        return self.api.crypto_box_open_afternm(encrypted, nonce, key)