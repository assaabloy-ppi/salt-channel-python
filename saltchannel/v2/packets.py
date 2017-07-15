from enum import Enum
from ctypes import *

from .exceptions import BadTicket
import saltchannel.util as util


class PacketType(Enum):
    """Packet type constants."""
    TYPE_M1 = 1
    TYPE_M2 = 2
    TYPE_M3 = 3
    TYPE_M4 = 4
    TYPE_APP_MESSAGE = 5
    TYPE_ENCRYPTED_MESSAGE = 6
    TYPE_TICKET = 7
    TYPE_A1 = 8
    TYPE_A2 = 9
    TYPE_TT = 10
    TYPE_TICKET_ENCRYPTED = 11


class SmartStructure(LittleEndianStructure):
    _pack_ = 1

    def __init__(self, **kwargs):
        values = dict()
        try:
            values = type(self)._defaults_.copy()
            for (key, val) in kwargs.items():
                values[key] = val
        except AttributeError:
            pass  # do nothing if there are no _defaults_ defined
        super().__init__(**values)

    def from_bytes(self, src):
        if src:
            memmove(addressof(self), src, min(len(src), sizeof(self)))

    @property
    def size(self):
        return sizeof(self)

    def __len__(self):
        """Let's len() return number of bytes."""
        return sizeof(self)


class Packet:
    """Abstract packet with fixed field set and optional part (self.opt)"""

    class _EmptyBodyOpt(SmartStructure):
        _fields_ = []

    def _opt_factory(self, body=None):
        return Packet._EmptyBodyOpt()

    def create_opt_fields(self):
        self.opt = self._opt_factory(body=self.data)

    def __init__(self):
        self.opt = self._opt_factory(body=None)

    def __bytes__(self):
        return b''.join([bytes(self.data), bytes(self.opt)])

    def from_bytes(self, src):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=self.data)
        self.opt.from_bytes(src[self.data.size:])

    @property
    def size(self):
        """Returns size of packet when serialized to a bytearray."""
        return len(self.data) + len(self.opt)


class M1Packet(Packet):
    """Data of the M1 message, low-level serialization/deserialization."""

    class _M1PacketBody(SmartStructure):
        class _M1PacketHeader(SmartStructure):
            # M1 header fields
            _fields_ = [('PacketType', c_uint8),
                        ('ServerSigKeyIncluded', c_uint8, 1),
                        ('TicketIncluded', c_uint8, 1),
                        ('TicketRequested', c_uint8, 1),
                        ('_reserved', c_uint8, 5)]
        # M1 body fields
        _fields_ = [('ProtocolIndicator', c_uint8 * 4),
                    ('Header', _M1PacketHeader),
                    ('Time', c_uint32),
                    ('ClientEncKey', c_uint8 * 32)]

        # M1 body fields defaults
        _defaults_ = {
            "ProtocolIndicator": util.cbytes(b'SCv2'),
        }

    def _opt_factory(self, body=None):
        if body is None:
            return Packet._EmptyBodyOpt()

        class _M1PacketBodyOpt(SmartStructure):
            # M1 body opt fields
            _fields_ = [('ServerSigKey', c_uint8 * (32 * body.Header.ServerSigKeyIncluded)),
                        ('TicketSize', c_uint8 * (1 * body.Header.TicketIncluded))]
        return _M1PacketBodyOpt()

    def __init__(self, src_buf=None, ticket=b''):
        self.data = M1Packet._M1PacketBody()
        self.data.Header.PacketType = PacketType.TYPE_M1.value
        self.opt = self._opt_factory()
        self._ticket = bytes(ticket)
        if src_buf:
            self.from_bytes(src_buf)

    def __bytes__(self):
        return b''.join([bytes(self.data), bytes(self.opt), self._ticket])

    def from_bytes(self, src):
        super().from_bytes(src)
        if self.data.Header.TicketIncluded == 1 and self.opt.TicketSize != 0:
            offset = sizeof(self.data)+sizeof(self.opt)
            self._ticket = bytes(src[offset:offset + self.opt.TicketSize[0]])

    @property
    def size(self):
        """Returns size of packet when serialized to a bytearray."""
        return len(self.data) + len(self.opt) + len(self._ticket)

    @property
    def Ticket(self):
        return self._ticket

    @Ticket.setter
    def Ticket(self, value):
        if self.data.Header.TicketIncluded != 1:
            raise AttributeError("Header.TicketIncluded != 1. Please set it explicitly before create_opt_fields() call.")
        self._ticket = value
        self.opt.TicketSize = util.cbytes(bytes([len(value)]))

    @property
    def ServerSigKey(self):
        return bytes(self.opt.ServerSigKey)

    @ServerSigKey.setter
    def ServerSigKey(self, value):
        if self.data.Header.ServerSigKeyIncluded != 1:
            raise AttributeError("Header.ServerSigKeyIncluded != 1. Please set it explicitly before create_opt_fields() call.")
        self.opt.ServerSigKey = util.cbytes(value)

    @property
    def ClientEncKey(self):
        return bytes(self.data.ClientEncKey)

    @ClientEncKey.setter
    def ClientEncKey(self, value):
        self.data.ClientEncKey = util.cbytes(value)


class M2Packet(Packet):
    """Data of the M2 message, low-level serialization/deserialization."""

    class _M2PacketBody(SmartStructure):
        class _M2PacketHeader(SmartStructure):
            # M2 header fields
            _fields_ = [('PacketType', c_uint8),
                        ('NoSuchServer', c_uint8, 1),
                        ('ResumeSupported', c_uint8, 1),
                        ('_reserved', c_uint8, 6)]
        # M2 body fields
        _fields_ = [('Header', _M2PacketHeader),
                    ('Time', c_uint32),
                    ('ServerEncKey', c_uint8 * 32)]

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = M2Packet._M2PacketBody()
        self.data.Header.PacketType = PacketType.TYPE_M2.value
        if src_buf:
            self.from_bytes(src_buf)

    @property
    def ServerEncKey(self):
        return bytes(self.data.ServerEncKey)

    @ServerEncKey.setter
    def ServerEncKey(self, value):
        self.data.ServerEncKey = util.cbytes(value)