import tweetnacl.raw as tweetnacl

from saltchannel.util.py import Singleton
from saltchannel.saltlib.saltlib_base import SaltLibBase
from saltchannel.saltlib.saltlib_base import BadSignatureException
from saltchannel.saltlib.saltlib_base import BadEncryptedDataException

class SaltLibTweetNaClExt(SaltLibBase, metaclass=Singleton):

    @staticmethod
    def isAvailable():
        return True

    # ret: pk, sk
    def crypto_sign_keypair_not_random(self, seed):
        if len(seed) != self.crypto_sign_SEEDBYTES:
            raise ValueError("Invalid seed")
        return tweetnacl.crypto_sign_seed_keypair(seed)

    # ret: sm
    def crypto_sign(self, m, sk):
        return tweetnacl.crypto_sign(m, sk)

    # ret: m
    def crypto_sign_open(self, sm, pk):
        try:
            return tweetnacl.crypto_sign_open(sm, pk)
        except Exception as e:
            raise BadSignatureException(e)

    # ret: k
    def crypto_box_beforenm(self, pk, sk):
        return tweetnacl.crypto_box_beforenm(pk, sk)

    # ret: c
    def crypto_box_afternm(self, m, n, k):
        return tweetnacl.crypto_box_afternm(m, n, k)

    # ret: m
    def crypto_box_open_afternm(self, c, n, k):
        try:
            return tweetnacl.crypto_box_open_afternm(c, n, k)
        except Exception as e:
            raise BadEncryptedDataException(e)

    # ret: pk, sk
    def crypto_box_keypair_not_random(self, sk):
        if len(sk) != self.crypto_box_SECRETKEYBYTES:
            raise ValueError("Invalid secret key length")
        return tweetnacl.crypto_scalarmult_base(sk), sk

    def crypto_hash(self, m):
        return tweetnacl.crypto_hash(m)