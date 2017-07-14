from enum import Enum
from abc import abstractmethod
from ctypes import * #LittleEndianStructure, Union, c_uint8, c_uint16

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

    def __len__(self):
        """Let's len() return number of bytes."""
        return sizeof(self)

#
#


class Packet:
    pass

class M1Packet(Packet):
    """Data of the M1 message, low-level serialization/deserialization."""

    class _M1PacketHeader(SmartStructure):
        _pack_ = 1
        # M1 header fields
        _fields_ = [('PacketType', c_uint8),
                    ('ServerSigKeyIncluded', c_uint8, 1),
                    ('TicketIncluded', c_uint8, 1),
                    ('TicketRequested', c_uint8, 1),
                    ('_reserved', c_uint8, 5)]
        # M1 header fields defaults
        _defaults_ = {
            "PacketType": PacketType.TYPE_M1.value,
        }

    def _m1_body_factory(self, header, **kwargs):
        class _M1PacketBody(SmartStructure):
            _pack_ = 1
            # M1 body fields
            _fields_ = [('ProtocolIndicator', c_uint8 * 4),
                        ('Header', M1Packet._M1PacketHeader),
                        ('Time', c_uint32),
                        ('ClientEncKey', c_uint8 * 32),
                        ('ServerSigKey', c_uint8 * (32 * header.ServerSigKeyIncluded)),
                        ('TicketSize', c_uint8 * header.TicketIncluded)]

            # M1 body fields defaults
            _defaults_ = {
                "ProtocolIndicator": util.cbytes(b'SCv2'),
            }
        return _M1PacketBody(**kwargs)

    def __init__(self, src_buf=None, ticket=b'', **kwargs):
        self.data = self._m1_body_factory(self._M1PacketHeader(**kwargs))
        self.Ticket = bytes(ticket)
        if src_buf:
            self.from_bytes(src_buf)

    def __bytes__(self):
        return b''.join([bytes(self.data), self.Ticket])

    def from_bytes(self, src):
        self.data.from_bytes(src)
        if self.data.Header.TicketIncluded == 1 and self.data.TicketSize != 0:
            self.Ticket = bytes(src[sizeof(self.data):sizeof(self.data) + self.data.TicketSize])

    @property
    def size(self):
        """Returns size of packet when serialized to a bytearray."""
        return len(self.data) + len(self.Ticket)


