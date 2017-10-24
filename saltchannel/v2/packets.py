from enum import Enum
from ctypes import *
from abc import ABCMeta

from ..exceptions import BadPeer as BadPeer

import saltchannel.util as util


class PacketType(Enum):
    """Packet type constants."""
    TYPE_M1 = 1
    TYPE_M2 = 2
    TYPE_M3 = 3
    TYPE_M4 = 4
    TYPE_APP_PACKET = 5
    TYPE_ENCRYPTED_PACKET = 6
    TYPE_A1 = 8
    TYPE_A2 = 9
    TYPE_MULTIAPP_PACKET = 11


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


class Packet(metaclass=ABCMeta):
    """Abstract packet with fixed field set and optional part (self.opt)"""

    class _EmptyBodyOpt(SmartStructure):
        _fields_ = []

    def _opt_factory(self, body=None):
        return Packet._EmptyBodyOpt()

    def create_opt_fields(self, **kwargs):
        self.opt = self._opt_factory(body=self.data, **kwargs)

    def __init__(self):
        self.opt = self._opt_factory(body=None)

    def __bytes__(self):
        return b''.join([bytes(self.data), bytes(self.opt)])

    def validate(self):
        """Check packet for consistency. Raise BadPeer() inside if something is wrong"""
        if self.data.Header.PacketType != type(self).TYPE:
            raise BadPeer("bad packet type: ", self.data.Header.PacketType)
        #TODO: test data 0xdeadbeef should be changed to other value to pass this validation
        #if self.data.Time > 0x7fffffff:
        #    raise BadPeer("Time field range is invalid")

    def from_bytes(self, src, validate=True):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=self.data)
        self.opt.from_bytes(src[self.data.size:])
        if validate:
            self.validate()

    def __getattr__(self, name):
        if not isinstance(getattr(type(self), name, None), property):
            return bytes(getattr(self.data, name))
        else:
            return object.__getattr__(self, name)

    def __setattr__(self, name, value):
        if name in ["data", "opt"] or isinstance(getattr(type(self), name, None), property):
            super().__setattr__(name, value)
        else:
            setattr(self.data, name, util.cbytes(value))

    @property
    def size(self):
        """Returns size of packet when serialized to a bytearray."""
        return len(self.data) + len(self.opt)



class M1Packet(Packet):
    """Data of the M1 message, low-level serialization/deserialization."""
    TYPE = PacketType.TYPE_M1.value

    class _M1PacketBody(SmartStructure):
        class _M1PacketHeader(SmartStructure):
            # M1 header fields
            _fields_ = [('PacketType', c_uint8),
                        ('ServerSigKeyIncluded', c_uint8, 1),
                        ('_reserved', c_uint8, 5)]
        # M1 body fields
        _fields_ = [('ProtocolIndicator', c_uint8 * 4),
                    ('Header', _M1PacketHeader),
                    ('Time', c_uint32),
                    ('ClientEncKey', c_uint8 * 32)]

        # M1 body fields defaults
        _defaults_ = {
            "ProtocolIndicator": (util.cbytes(b'SCv2')),
        }

    def _opt_factory(self, body=None):
        if body is None:
            return Packet._EmptyBodyOpt()

        class _M1PacketBodyOpt(SmartStructure):
            # M1 body opt fields
            _fields_ = [('ServerSigKey', c_uint8 * (32 * body.Header.ServerSigKeyIncluded))]
        return _M1PacketBodyOpt()

    def __init__(self, src_buf=None):
        self.data = M1Packet._M1PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        self.opt = self._opt_factory()
        if src_buf:
            self.from_bytes(src_buf)

    def __bytes__(self):
        return b''.join([bytes(self.data), bytes(self.opt)])

    def from_bytes(self, src):
        super().from_bytes(src, validate=False)  # validate at the end of this method instead
        self.validate()

    def validate(self):
        """Check packet for consistency. Raise BadPeer() inside if something is wrong"""
        super().validate()
        if self.data.ProtocolIndicator[:] != self.data._defaults_['ProtocolIndicator'][:]:
            raise BadPeer("unexpected ProtocolIndicator: ", bytes(self.data.ProtocolIndicator))

    @property
    def size(self):
        """Returns size of packet when serialized to a bytearray."""
        return len(self.data) + len(self.opt)

    @property
    def ServerSigKey(self):
        return bytes(self.opt.ServerSigKey)

    @ServerSigKey.setter
    def ServerSigKey(self, value):
        if self.data.Header.ServerSigKeyIncluded != 1:
            raise AttributeError("Header.ServerSigKeyIncluded != 1. Please set it explicitly before create_opt_fields() call.")
        self.opt.ServerSigKey = util.cbytes(value)


class M2Packet(Packet):
    """Data of the M2 message, low-level serialization/deserialization."""
    TYPE = PacketType.TYPE_M2.value

    class _M2PacketBody(SmartStructure):
        class _M2PacketHeader(SmartStructure):
            # M2 header fields
            _fields_ = [('PacketType', c_uint8),
                        ('NoSuchServer', c_uint8, 1),
                        ('_reserved', c_uint8, 6),
                        ('LastFlag', c_uint8, 1),
                        ]
        # M2 body fields
        _fields_ = [('Header', _M2PacketHeader),
                    ('Time', c_uint32),
                    ('ServerEncKey', c_uint8 * 32)]

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = M2Packet._M2PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        if src_buf:
            self.from_bytes(src_buf)


class M3Packet(Packet):
    """Data of the M3 message, low-level serialization/deserialization."""
    TYPE = PacketType.TYPE_M3.value
    SIG1_PREFIX = b'SC-SIG01'

    class _M3PacketBody(SmartStructure):
        class _M3PacketHeader(SmartStructure):
            # M3 header fields
            _fields_ = [('PacketType', c_uint8),
                        ('_reserved', c_uint8)]
        # M3 body fields
        _fields_ = [('Header', _M3PacketHeader),
                    ('Time', c_uint32),
                    ('ServerSigKey', c_uint8 * 32),
                    ('Signature1', c_uint8 * 64)]

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = M3Packet._M3PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        if src_buf:
            self.from_bytes(src_buf)


class M4Packet(Packet):
    """Data of the M4 message, low-level serialization/deserialization."""
    TYPE = PacketType.TYPE_M4.value
    SIG2_PREFIX = b'SC-SIG02'

    class _M4PacketBody(SmartStructure):
        class _M4PacketHeader(SmartStructure):
            # M4 header fields
            _fields_ = [('PacketType', c_uint8),
                        ('_reserved', c_uint8)]
        # M3 body fields
        _fields_ = [('Header', _M4PacketHeader),
                    ('Time', c_uint32),
                    ('ClientSigKey', c_uint8 * 32),
                    ('Signature2', c_uint8 * 64)]

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = M4Packet._M4PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        if src_buf:
            self.from_bytes(src_buf)


class EncryptedPacket(Packet):
    """Encrypted container for M3/M4/AppPacket. """
    TYPE = PacketType.TYPE_ENCRYPTED_PACKET.value

    class _EncryptedPacketBody(SmartStructure):
        class _EncryptedPacketHeader(SmartStructure):
            # EncryptedPacket header fields
            _fields_ = [('PacketType', c_uint8),
                        ('_reserved', c_uint8, 7),
                        ('LastFlag', c_uint8, 1),
                        ]
        # EncryptedPacket body fields
        _fields_ = [('Header', _EncryptedPacketHeader)]

    def _opt_factory(self, body=None, body_field_len=0):
        if body is None:
            return Packet._EmptyBodyOpt()

        if body_field_len < 0:
            raise BadPeer("'Body' field size requested too small: ", body_field_len)

        class _EncryptedPacketBodyOpt(SmartStructure):
            # EncryptedPacket opt/variable fields
            _fields_ = [('Body', c_uint8 * body_field_len)]
        return _EncryptedPacketBodyOpt()

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = EncryptedPacket._EncryptedPacketBody()
        self.data.Header.PacketType = type(self).TYPE
        if src_buf:
            self.from_bytes(src_buf)

    def from_bytes(self, src, validate=True):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=src, body_field_len=len(src)-2)
        self.opt.from_bytes(src[self.data.size:])
        if validate:
            self.validate()

    def validate(self):
        super().validate()
        if len(self.Body) < 16:
            raise BadPeer("'Body' field value is too small")

    @property
    def Body(self):
        return bytes(self.opt.Body)

    @Body.setter
    def Body(self, value):
        self.opt = self._opt_factory(body=value, body_field_len=len(value))
        self.opt.Body = util.cbytes(value)


class AppPacket(Packet):
    TYPE = PacketType.TYPE_APP_PACKET.value

    class _AppPacketBody(SmartStructure):
        class _AppPacketHeader(SmartStructure):
            # AppPacket header fields
            _fields_ = [('PacketType', c_uint8),
                        ('_reserved', c_uint8)]
        # AppPacket body fields
        _fields_ = [('Header', _AppPacketHeader),
                    ('Time', c_uint32)]

    def _opt_factory(self, body=None, data_field_len=0):
        if body is None:
            return Packet._EmptyBodyOpt()

        if data_field_len < 0:
            raise BadPeer("'Data' field size requested too small: ", data_field_len)

        class _AppPacketBodyOpt(SmartStructure):
            # AppPacket opt/variable fields
            _fields_ = [('Data', c_uint8 * data_field_len)]
        return _AppPacketBodyOpt()

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = AppPacket._AppPacketBody()
        self.data.Header.PacketType = type(self).TYPE
        if src_buf:
            self.from_bytes(src_buf)

    def from_bytes(self, src, validate=True):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=src, data_field_len=len(src)-6)
        self.opt.from_bytes(src[self.data.size:])
        if validate:
            self.validate()

    @property
    def Data(self):
        return bytes(self.opt.Data)

    @Data.setter
    def Data(self, value):
        self.opt = self._opt_factory(body=value, data_field_len=len(value))
        self.opt.Data = util.cbytes(value)

# leaved here for now
class TTPacket(Packet):
    SESSION_NONCE_SIZE = 8
