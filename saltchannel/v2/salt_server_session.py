import logging
import pprint

from ..saltlib import SaltLib
from ..saltlib.saltlib_base import SaltLibBase
from ..util.time import NullTimeChecker, NullTimeKeeper
from ..util.key_pair import KeyPair
from . import packets
from . import ticket
#import exceptions
import saltchannel.saltlib.exceptions
from .encrypted_channel_v2 import EncryptedChannelV2, Role
from .app_channel_v2 import AppChannelV2


class SaltServerSession:
    """Server-side implementation of a Salt Channel v2 session.
    Usage: create object, set or create ephemeral key, use other setX methods,
    call handshake(), get resulting encrypted ByteChannel to use by
    application layer.
    Do not reuse the object for more than one Salt Channel session.
    Limitation: does not support virtual servers, just one pubkey supported.
    """

    def __init__(self, sig_keypair, clear_channel):
        self.saltlib = SaltLib()
        self.sig_keypair = sig_keypair

        self.clear_channel = clear_channel
        self.app_channel = None  # AppChannelV2
        self.enc_channel = None  # EncryptedChannelV2

        self.time_keeper = NullTimeKeeper()  # singleton
        self.time_checker = NullTimeChecker()  # singleton

        self.enc_keypair = None
        self.resume_handler = None

        self.m1 = None
        self.m1_hash = b''
        self.m2 = None
        self.m2_hash = b''
        self.m4 = None

        self.buffer_m2 = False
        self.client_sig_key = None

    def handshake(self):
        self.validate()
        (valid_m1, resumed, recv_chunk) = self.do_m1()

        if not valid_m1:
            self.do_a2(recv_chunk)
            return

        if resumed:
            return

        self.do_m2()
        self.create_encrypted_channel()

        self.do_m3()
        self.do_m4()
        self.validate_signature2()
        self.tt()

    def do_a2(data_chunk):
        raise  NotImplemented()

    def do_m1(self):
        """Returns tuple (valid_m1, resumed, read_chunk)"""
        clear_chunk = self.clear_channel.read()
        self.m1 = packets.M1Packet(src_buf=clear_chunk)

        if self.m1.data.Header.PacketType != packets.PacketType.TYPE_M1.value:
            self.m1 = None
            return (False, False, clear_chunk)  # it' not M1, falling back...

        # M1 processing
        self.time_checker.report_first_time(self.m1.data.Time)
        self.m1_hash = self.saltlib.sha512(clear_chunk)
        if self.m1.data.Header.ServerSigKeyIncluded and self.sig_keypair.pub != self.m1.ServerSigKey:
            m2 = packets.M2Packet()
            m2.data.Time = self.time_keeper.get_first_time()
            m2.data.Header.NoSuchServer = 1
            self.clear_channel.write(bytes(m2))
            raise exceptions.NoSuchServerException()

        # Ticket processing
        if self.m1.data.Header.TicketIncluded and self.resume_handler:
            raise NotImplementedError()
            # return (True,True, None)

        return (True,False, None)

    def do_m2(self):
        self.m2 = packets.M2Packet()
        self.m2.data.Time = self.time_keeper.get_first_time()
        self.m2.data.Header.ResumeSupported = 1 if self.resume_handler else 0
        self.m2.ServerEncKey = self.enc_keypair.pub

        if not self.buffer_m2:
            self.clear_channel.write(bytes(self.m2))  # check for copy overhead here
            self.m2_hash = self.saltlib.sha512(bytes(self.m2)) # check for copy overhead here

    def do_m3(self):
        time = 0
        msg_list = []

        if self.buffer_m2:
            time = self.time_keeper.get_first_time()
            self.m2.data.Time = time
            self.m2_hash = self.saltlib.sha512(bytes(self.m2))
            msg_list.append(bytes(self.m2))
        else:
            time = self.time_keeper.get_time()

        p = packets.M3Packet()
        p.data.Time = time
        p.ServerSigKey = self.sig_keypair.pub
        p.Signature1 = self.saltlib.sign(b''.join([self.m1_hash, self.m2_hash]), self.sig_keypair.sec)[:SaltLibBase.crypto_sign_BYTES]

        msg_list.append(self.enc_channel.wrap(self.enc_channel.encrypt(bytes(p))))
        self.enc_channel.write_nonce.advance()

        self.clear_channel.write(msg_list[0], *(msg_list[1:]))

    def do_m4(self):
        self.m4 = packets.M4Packet(src_buf=self.enc_channel.read())
        self.time_checker.check_time(self.m4.data.Time)
        self.client_sig_key = self.m4.ClientSigKey

    def tt(self):
        """Sends TT message if this server supports resume and the client requested a ticket."""
        if not self.resume_handler:
            return

        if self.m1.data.Header.TicketRequested:
            raise NotImplementedError

    def create_encrypted_channel(self):
        self.session_key = self.saltlib.compute_shared_key(self.enc_keypair.sec, self.m1.ClientEncKey)
        self.enc_channel = EncryptedChannelV2(self.clear_channel, self.session_key, Role.SERVER)
        self.app_channel = AppChannelV2(self.enc_channel, self.time_keeper, self.time_checker)

    def create_encrypted_channel_for_resumed(self, ts_data):
        self.session_key = ts_data.session_key
        self.client_sig_key = ts_data.client_sig_key
        self.enc_channel = EncryptedChannelV2(self.clear_channel, self.session_key, Role.SERVER,
                                              ts_data.session_nonce)
        self.app_channel = AppChannelV2(self.enc_channel, self.time_keeper, self.time_checker)

    def validate_signature2(self):
        """Validates M4/Signature2."""
        try:
            self.saltlib.sign_open(b''.join([self.m4.Signature2, self.m1_hash, self.m2_hash]), self.m4.ClientSigKey)
        except saltchannel.saltlib.exceptions.BadSignatureException:
            raise saltchannel.exceptions.BadPeer("invalid signature")


    def validate(self):
        """Check if current instance's state is valid for handshake to start"""
        if not self.enc_keypair:
            raise ValueError("'enc_keypair' must be set before calling handshake()")
