import asyncio

from ..saltlib import SaltLib
from ..saltlib.saltlib_base import SaltLibBase
from ..util.time import NullTimeChecker, NullTimeKeeper
from .packets import *
from saltchannel.a1a2.packets import *
import saltchannel.util as util

import saltchannel.saltlib.exceptions
from .encrypted_channel_v2 import EncryptedChannelV2, Role
from .app_channel_v2 import AppChannelV2


class SaltServerSession(metaclass=util.Syncizer):
    """Server-side implementation of a Salt Channel v2 session.
    Asyncio-based implementation
    """

    def __init__(self, sig_keypair, clear_channel, loop=None):
        self.loop = util.force_event_loop(loop=loop)
        
        self.saltlib = SaltLib()
        self.sig_keypair = sig_keypair

        self.clear_channel = clear_channel
        self.app_channel = None  # AppChannelV2
        self.enc_channel = None  # EncryptedChannelV2

        self.time_keeper = NullTimeKeeper()  # singleton
        self.time_checker = NullTimeChecker()  # singleton

        self.enc_keypair = None

        self.m1 = None
        self.m1_hash = b''
        self.m2 = None
        self.m2_hash = b''
        self.m4 = None

        self.is_done = False

        self.buffer_m2 = False
        self.client_sig_key = None

    async def handshake(self):
        self.validate()
        (valid_m1, resumed, recv_chunk) = await self.do_m1()

        if not valid_m1:
            await self.do_a2(recv_chunk)
            self.is_done = True
            return

        self.validate()

        if resumed:
            return

        await self.do_m2()
        self.create_encrypted_channel()

        await self.do_m3()
        await self.do_m4()
        self.validate_signature2()

    async def do_a2(self, data_chunk):
        a1 = A1Packet(src_buf=data_chunk)
        a2 = A2Packet(case=A2Packet.Case.A2_NO_SUCH_SERVER
                                if a1.AddressType == A1Packet.ADDRESS_TYPE_PUBKEY and
                                   a1.Address != self.sig_keypair.pub
                                else A2Packet.Case.A2_DEFAUT)
        await self.clear_channel.write(bytes(a2), is_last=True)

    async def do_m1(self):
        """Returns tuple (valid_m1, resumed, read_chunk)"""
        clear_chunk = await self.clear_channel.read()

        self.m1 = M1Packet(src_buf=clear_chunk)

        if self.m1.data.Header.PacketType != PacketType.TYPE_M1.value:
            self.m1 = None
            return (False, False, clear_chunk)  # it' not M1, falling back...

        # M1 processing
        self.time_checker.report_first_time(self.m1.data.Time)
        self.m1_hash = self.saltlib.sha512(clear_chunk)
        if self.m1.data.Header.ServerSigKeyIncluded and self.sig_keypair.pub != self.m1.ServerSigKey:
            m2 = M2Packet()
            m2.data.Time = self.time_keeper.get_first_time()
            m2.data.Header.NoSuchServer = 1
            await self.clear_channel.write(bytes(m2), is_last=True)
            raise saltchannel.exceptions.NoSuchServerException()

        return (True,False, None)

    async def do_m2(self):
        self.m2 = M2Packet()
        self.m2.data.Time = self.time_keeper.get_first_time()
        self.m2.ServerEncKey = self.enc_keypair.pub

        if not self.buffer_m2:
            await self.clear_channel.write(bytes(self.m2))  # check for copy overhead here
            self.m2_hash = self.saltlib.sha512(bytes(self.m2)) # check for copy overhead here

    async def do_m3(self):
        time = 0
        msg_list = []

        if self.buffer_m2:
            time = self.time_keeper.get_first_time()
            self.m2.data.Time = time
            self.m2_hash = self.saltlib.sha512(bytes(self.m2))
            msg_list.append(bytes(self.m2))
        else:
            time = self.time_keeper.get_time()

        p = M3Packet()
        p.data.Time = time
        p.ServerSigKey = self.sig_keypair.pub
        p.Signature1 = self.saltlib.sign(b''.join([M3Packet.SIG1_PREFIX, self.m1_hash, self.m2_hash]),
                                         self.sig_keypair.sec)[:SaltLibBase.crypto_sign_BYTES]

        msg_list.append(self.enc_channel.wrap(self.enc_channel.encrypt(bytes(p)), is_last=False))
        self.enc_channel.write_nonce.advance()

        await self.clear_channel.write(msg_list[0], *(msg_list[1:]))

    async def do_m4(self):
        self.m4 = M4Packet(src_buf=await self.enc_channel.read())
        self.time_checker.check_time(self.m4.data.Time)
        self.client_sig_key = self.m4.ClientSigKey

    def create_encrypted_channel(self):
        self.session_key = self.saltlib.compute_shared_key(self.enc_keypair.sec, self.m1.ClientEncKey)
        self.enc_channel = EncryptedChannelV2(self.clear_channel, self.session_key, Role.SERVER)
        self.app_channel = AppChannelV2(self.enc_channel, self.time_keeper, self.time_checker)

    def validate_signature2(self):
        """Validates M4/Signature2."""
        try:
            self.saltlib.sign_open(b''.join([self.m4.Signature2, M4Packet.SIG2_PREFIX,
                                             self.m1_hash, self.m2_hash]), self.m4.ClientSigKey)
        except saltchannel.saltlib.exceptions.BadSignatureException:
            raise saltchannel.exceptions.BadPeer("invalid signature")

    def validate(self):
        """Check if current instance's state is valid for handshake to start"""
        if not self.enc_keypair:
            raise ValueError("'enc_keypair' must be set before calling handshake()")