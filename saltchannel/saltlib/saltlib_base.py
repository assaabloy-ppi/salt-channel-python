# -*- coding: utf-8 -*-

from abc import abstractmethod
from saltchannel.util import SingletonABCMeta


class SaltLibBase(metaclass=SingletonABCMeta):

    crypto_sign_PUBLICKEYBYTES = 32
    crypto_sign_SECRETKEYBYTES = 64
    crypto_sign_BYTES = 64
    crypto_sign_SEEDBYTES = 32

    crypto_box_PUBLICKEYBYTES = 32
    crypto_box_SECRETKEYBYTES = 32
    crypto_box_SHAREDKEYBYTES = 32
    crypto_box_BEFORENMBYTES = 32
    crypto_box_NONCEBYTES = 24
    crypto_box_ZEROBYTES = 32
    crypto_box_BOXZEROBYTES = 16
    crypto_box_OVERHEADBYTES = 16
    crypto_box_INTERNALOVERHEADBYTES = 32

    crypto_hash_BYTES = 64

    @staticmethod
    #@abstractmethod
    def isAvailable():  pass

    #@abstractmethod
    def getName(self):  pass

    @abstractmethod
    def crypto_sign_keypair_not_random(self, sk):  pass

    @abstractmethod
    def crypto_sign(self, m, sk):  pass

    @abstractmethod
    def crypto_sign_open(self, sm, pk):  pass

    @abstractmethod
    def crypto_box_keypair_not_random(self, sk):  pass

    @abstractmethod
    def crypto_box_beforenm(self, pk, sk):  pass

    @abstractmethod
    def crypto_box_afternm(self, m, n, k):  pass

    @abstractmethod
    def crypto_box_open_afternm(self, c, n, k):  pass

    @abstractmethod
    def crypto_hash(self, m):  pass

    @abstractmethod
    def randombytes(self, n):  pass
