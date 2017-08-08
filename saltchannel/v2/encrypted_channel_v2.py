from enum import Enum

from ..saltlib import SaltLib
from ..saltlib import BadEncryptedDataException, BadSignatureException
from ..channel import ByteChannel
from .packets import EncryptedPacket, TTPacket
from ..exceptions import BadPeer


class Role(Enum):
    """Role of this peer of the encrypted channel. Used for nonce handling."""
    CLIENT = 1,
    SERVER = 2


class NonceType(Enum):
    """"""
    READ = 1,
    WRITE = 2


class Nonce:
    def __init__(self, nonce_type, session_nonce, value=0):
        self.nonce_type = nonce_type
        self.session_nonce = session_nonce
        self.value = value

    def advance(self):
        self.value += 2

    def __bytes__(self):
        return b''.join([self.value.to_bytes(8, 'little'), self.session_nonce, bytes(8)])


class EncryptedChannelV2(ByteChannel):
    """An implementation of an encrypted channel using a shared symmetric session key.
    The read/write methods throws ComException for low-level IO errors
    and BadPeer if the data format is not OK or if the data is not
    encrypted properly."""

    def __init__(self, channel, key, role, session_nonce=bytes(TTPacket.SESSION_NONCE_SIZE)):
        self.saltlib = SaltLib().getLib()  # refactor to self.salt ?

        if len(key) != self.saltlib.crypto_box_SECRETKEYBYTES:
            raise ValueError("bad key size, should be " + self.saltlib.crypto_box_SECRETKEYBYTES)

        self.key = key
        self.channel = channel
        self.pushback_msg = b''  # used for Resume feature when happens just read chunk is encrypted

        self.read_nonce = Nonce(NonceType.READ, session_nonce, value= 2 if role == Role.CLIENT else 1)
        self.write_nonce = Nonce(NonceType.WRITE, session_nonce, value= 1 if role == Role.CLIENT else 2)

    def read(self):
        if self.pushback_msg:
            raw = self.pushback_msg
            self.pushback_msg = None
        else:
            raw = self.channel.read()

        clear = self.decrypt(self.unwrap(raw))
        self.read_nonce.advance()
        return clear

    def write(self, message, *args):
        raw = bytearray()
        for msg in (message,) + args:
            raw.extend(self.wrap(self.encrypt(msg)))
            self.write_nonce.advance()
        self.channel.write(raw)

    def encrypt(self, clear):
        return self.saltlib.crypto_box_afternm(clear, bytes(self.write_nonce), self.key)

    def decrypt(self, encrypted):
        try:
            return self.saltlib.crypto_box_open_afternm(encrypted, bytes(self.read_nonce), self.key)
        except BadEncryptedDataException:
            raise BadPeer("invalid ciphertext, could not be decrypted")

    def wrap(self, src_bytes):
        """Wrap encrypted bytes in EncryptedPacket"""
        ep = EncryptedPacket()
        ep.Body = src_bytes
        return bytes(ep)

    def unwrap(self, ep_bytes):
        """Extract body from EncryptedPacket bytes"""
        return EncryptedPacket(src_buf=ep_bytes).Body
