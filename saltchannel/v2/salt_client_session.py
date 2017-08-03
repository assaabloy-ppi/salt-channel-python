from saltlib import SaltLib
from util.time import NullTimeChecker, NullTimeKeeper
from util.key_pair import KeyPair
from . import packets
from . import ticket
import exceptions
import saltlib.exceptions
from .encrypted_channel_v2 import EncryptedChannelV2, Role
from .app_channel_v2 import AppChannelV2


class SaltClientSession:
    """Client-side implementation of a Salt Channel v2 session.
    Usage: create object, set or create ephemeral key,
    call handshake(), get resulting encrypted channel (getChannel())
    to use by application layer. Use getServerSigKey() to get the server's pubkey.
    Do not reuse the object for more than one Salt Channel session.
    Limitation: does not support virtual servers, just one pubkey supported.
    For debug/inspection: the handshake messages (m1, m2, m3, m4) are stored.
    """

    def __init__(self, sig_keypair, clear_channel):
        self.saltlib = SaltLib().getLib()
        self.sig_keypair = sig_keypair

        self.clear_channel = clear_channel
        self.app_channel = None  # AppChannelV2
        self.enc_channel = None  # EncryptedChannelV2

        self.time_keeper = NullTimeKeeper()  # singleton
        self.time_checker = NullTimeChecker()  # singleton
        self.ticket_requested = False
        self.ticket_data = None
        self.ticket_data_new = None  # new ticket from server

        self.session_key = b''

        self.wanted_server_sig_key = b''
        self.enc_keypair = KeyPair(sec=None, pub=None)
        self.buffer_M4 = False

        self.m1 = None
        self.m1_hash = b''
        self.m2 = None
        self.m2_hash = b''
        self.m3 = None
        self.m4 = None
        self.tt = None

    def handshake(self):
        self.validate()
        self.m1()

        (success, recv_chunk) = self.m2()
        if not success:
            self.tt1(recv_chunk)
            return

        self.create_encrypted_channel()
        self.m3()
        self.validate_signature1()
        self.m4()
        self.tt2()


    def m1(self):
        """Creates and writes M1 message."""
        self.m1 = packets.M1Packet()
        self.m1.data.Time = self.time_keeper.get_first_time()
        self.m1.data.clientEncKey = self.enc_keypair.pub
        self.m1.data.serverSigKey = self.wanted_server_sig_key
        self.m1.data.Header.TicketRequested = self.ticket_requested

        if self.ticket_data:
            self.m1.Ticket = self.ticket_data.ticket

        m1_raw = bytes(self.m1)
        self.m1_hash = self.saltlib.sha512(m1_raw)

        self.clear_channel.write(m1_raw)

        if self.ticket_data:
            self.create_encrypted_channel_for_resumed()


    def m2(self):
        """Read m2 with fallback to raw chunk if no M2 packet type detected in Header."""
        clear_chunk = self.clear_channel.read()
        self.m2 = packets.M1Packet(src_buf=clear_chunk)
        if self.m2.data.Header.PacketType != packets.PacketType.TYPE_M2:
            self.m2 = None
            return (False, clear_chunk)  # it' not M2, falling back...

        # M2 processing
        if self.m2.data.Header.NoSuchServer:
            raise exceptions.NoSuchServerException()

        self.time_checker.report_first_time(self.m2.Time)
        self.m2_hash = self.saltlib.sha512(bytes(self.m2))
        return (True, None)

    def tt1(self, raw_chunk):
        """Processing TT Packet as first reply from the server"""
        ep = packets.EncryptedPacket(src_buf=raw_chunk)
        if ep.data.Header.PacketType != packets.PacketType.TYPE_ENCRYPTED_PACKET:
            raise exceptions.BadPeer("expected 'TYPE_ENCRYPTED_PACKET', but received: " + ep.data.Header.PacketType);

        if not self.enc_channel:
            raise exceptions.BadPeer("got TYPE_ENCRYPTED_PACKET', but not resumed channel exists")

        if not self.m1.Header.TicketRequested:
            raise exceptions.BadPeer("got a ticket, but none was requested")

        self.enc_channel.pushback_msg = raw_chunk

        tt = packets.TTPacket(src_buf=self.enc_channel.read())
        self.new_ticket_data = ticket.ClientTicketData(ticket=tt.ticket, session_key=self.session_key,
                                                       session_nonce=tt.session_nonce)

    def m3(self):
        self.m3 = packets.M3Packet(src_buf=self.enc_channel.read)
        self.time_checker.check_time(self.m3.Time)

    def m4(self):
        self.m4 = packets.M4Packet()
        self.m4.data.Time = self.time_keeper.get_time()
        self.m4.data.ClientSigKey = self.sig_keypair.pub
        self.m4.data.Signature2 = self.saltlib.sign(self.m1_hash.join(self.m2_hash), self.sig_keypair.sec)

        if self.buffer_M4:
            self.app_channel.buffered_m4 = self.m4
        else:
            self.enc_channel.write(bytes(self.m4))

    def tt2(self):
        """Reads TT packet from server after 3-way handshake."""
        if self.m1.Header.TicketRequested and self.m2.Header.ResumeSupported:
            tt = packets.TTPacket(src_buf=self.enc_channel.read())
            self.new_ticket_data = ticket.ClientTicketData(ticket=tt.ticket, session_key=self.session_key,
                                                           session_nonce=tt.session_nonce)

    def validate_signature1(self):
        """Validates M3/Signature1."""
        try:
            self.saltlib.sign_open(self.m3.data.Signature1.join(self.m1_hash, self.m2_hash), self.m3.data.ServerSigKey)
        except saltlib.exceptions.BadSignatureException:
            raise exceptions.BadPeer("invalid signature")

    def create_encrypted_channel(self):
        self.session_key = self.saltlib.compute_shared_key(self.enc_keypair.sec, self.m2.data.ServerEncKey)
        self.enc_channel = EncryptedChannelV2(self.clear_channel, self.session_key, Role.CLIENT)
        self.app_channel = AppChannelV2(self.enc_channel, self.time_keeper, self.time_checker)

    def create_encrypted_channel_for_resumed(self):
        self.session_key = self.ticket_data.session_key
        self.enc_channel = EncryptedChannelV2(self.clear_channel, self.session_key, Role.CLIENT,
                                              self.ticket_data.session_nonce)
        self.app_channel = AppChannelV2(self.enc_channel, self.time_keeper, self.time_checker)

    def validate(self):
        """Check if current instance's state is valid for handshake to start"""
        if not self.enc_keypair:
            raise ValueError("'enc_keypair' must be set before calling handshake()")