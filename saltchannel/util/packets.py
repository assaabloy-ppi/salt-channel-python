from enum import Enum
from ctypes import *
from abc import ABCMeta

import saltchannel.util as util
from ..exceptions import BadPeer as BadPeer


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