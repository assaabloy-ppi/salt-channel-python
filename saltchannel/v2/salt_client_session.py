import asyncio
from ..saltlib import SaltLib
from ..saltlib.saltlib_base import SaltLibBase
import saltchannel.util as util
from ..util.time import NullTimeChecker, NullTimeKeeper
from . import packets

import saltchannel.saltlib.exceptions
from .encrypted_channel_v2 import EncryptedChannelV2, Role
from .app_channel_v2 import AppChannelV2


class SaltClientSession(metaclass=util.Syncizer):
    """Client-side implementation of a Salt Channel v2 session.
    Asyncio-based implementation
    """
    def __init__(self, sig_keypair, clear_channel, loop=None):
        self.loop = loop or asyncio.new_event_loop()

        self.saltlib = SaltLib()
        self.sig_keypair = sig_keypair

        self.clear_channel = clear_channel
        self.app_channel = None  # AppChannelV2
        self.enc_channel = None  # EncryptedChannelV2

        self.time_keeper = NullTimeKeeper()  # singleton
        self.time_checker = NullTimeChecker()  # singleton

        self.session_key = b''

        self.wanted_server_sig_key = b''
        self.enc_keypair = None
        self.buffer_M4 = False

        self.m1 = None
        self.m1_hash = b''
        self.m2 = None
        self.m2_hash = b''
        self.m3 = None
        self.m4 = None

    async def handshake(self):
        self.validate()
        await self.do_m1()

        (success, recv_chunk) = await self.do_m2()
        if not success:
            return

        self.create_encrypted_channel()
        await self.do_m3()
        self.validate_signature1()
        await self.do_m4()

    async def do_m1(self):
        """Creates and writes M1 message."""
        self.m1 = packets.M1Packet()
        self.m1.create_opt_fields()
        self.m1.data.Time = self.time_keeper.get_first_time()
        self.m1.ClientEncKey = self.enc_keypair.pub

        m1_raw = bytes(self.m1)
        self.m1_hash = self.saltlib.sha512(m1_raw)

        await self.clear_channel.write(m1_raw)


    async def do_m2(self):
        """Read m2 with fallback to raw chunk if no M2 packet type detected in Header."""
        clear_chunk = await self.clear_channel.read()
        self.m2 = packets.M2Packet(src_buf=clear_chunk)
        if self.m2.data.Header.PacketType != packets.PacketType.TYPE_M2.value:
            self.m2 = None
            return (False, clear_chunk)  # it' not M2, falling back...

        # M2 processing
        self.time_checker.report_first_time(self.m2.data.Time)
        self.m2_hash = self.saltlib.sha512(clear_chunk)
        if self.m2.data.Header.NoSuchServer:
            raise saltchannel.exceptions.NoSuchServerException()

        return (True, None)

    async def do_m3(self):
        chunk = await self.enc_channel.read()
        assert(len(chunk) == 2+4+32+64)
        self.m3 = packets.M3Packet(src_buf=chunk)
        self.time_checker.check_time(self.m3.data.Time)

    async def do_m4(self):
        self.m4 = packets.M4Packet()
        self.m4.data.Time = self.time_keeper.get_time()
        self.m4.ClientSigKey = self.sig_keypair.pub
        self.m4.Signature2 = self.saltlib.sign(b''.join([packets.M4Packet.SIG2_PREFIX,self.m1_hash, self.m2_hash]),
                                               self.sig_keypair.sec)[:SaltLibBase.crypto_sign_BYTES]

        if self.buffer_M4:
            self.app_channel.buffered_m4 = self.m4
        else:
            await self.enc_channel.write(bytes(self.m4))

    def validate_signature1(self):
        """Validates M3/Signature1."""
        try:
            self.saltlib.sign_open(b''.join([self.m3.Signature1, packets.M3Packet.SIG1_PREFIX,
                                            self.m1_hash, self.m2_hash]), self.m3.ServerSigKey)
        except saltchannel.saltlib.exceptions.BadSignatureException:
            raise saltchannel.exceptions.BadPeer("invalid signature")

    def create_encrypted_channel(self):
        self.session_key = self.saltlib.compute_shared_key(self.enc_keypair.sec, self.m2.ServerEncKey)
        self.enc_channel = EncryptedChannelV2(self.clear_channel, self.session_key, Role.CLIENT)
        self.app_channel = AppChannelV2(self.enc_channel, self.time_keeper, self.time_checker)

    def validate(self):
        """Check if current instance's state is valid for handshake to start"""
        if not self.enc_keypair:
            raise ValueError("'enc_keypair' must be set before calling handshake()")