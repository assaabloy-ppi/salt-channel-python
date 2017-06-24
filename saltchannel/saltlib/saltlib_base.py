
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

    crypto_secretbox_KEY_BYTES = 32
    crypto_secretbox_NONCE_BYTES = 24
    crypto_secretbox_OVERHEAD_BYTES = 16
    crypto_secretbox_INTERNAL_OVERHEAD_BYTES = 32

    crypto_hash_BYTES = 64

    @staticmethod
    def isAvailable():
        raise NotImplementedError("SaltLibBase is abstract class")

    def getName(self):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_sign_keypair_not_random(self, pk, sk):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_sign(self, sm, m, sk):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_sign_open(self, m, sm, pk):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_box_keypair_not_random(self, pk, sk):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_box_beforenm(self, k, pk, sk):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_box_afternm(self, c, m, n, k):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_box_open_afternm(self, m, c, n, k):
        raise NotImplementedError("SaltLibBase is abstract class")

    def crypto_hash(self, h, m):
        raise NotImplementedError("SaltLibBase is abstract class")