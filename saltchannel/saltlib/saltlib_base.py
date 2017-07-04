from saltchannel.util.py import abstract

class BadSignatureException(RuntimeError):
    pass

class BadEncryptedDataException(RuntimeError):
    pass

class SaltLibBase:

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
    def isAvailable():  abstract()
    def getName(self):  abstract()
    # ret: pk, sk
    def crypto_sign_keypair_not_random(self, sk):  abstract()
    # ret: sm
    def crypto_sign(self, m, sk):  abstract()
    # ret: m
    def crypto_sign_open(self, sm, pk):  abstract()
    # ret: pk, sk
    def crypto_box_keypair_not_random(self, sk):  abstract()
    # ret: k
    def crypto_box_beforenm(self, pk, sk):  abstract()
    # ret: c
    def crypto_box_afternm(self, m, n, k):  abstract()
    # ret: m
    def crypto_box_open_afternm(self, c, n, k):  abstract()
    # ret: h
    def crypto_hash(self, m):  abstract()