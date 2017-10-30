import re

from saltchannel.util.packets import *
from ..exceptions import BadPeer as BadPeer


class A1Packet(Packet):
    TYPE = PacketType.TYPE_A1_PACKET.value
    ADDRESS_TYPE_ANY = 0
    ADDRESS_TYPE_PUBKEY = 1
    MAX_ADDRESS_LENGTH = 65535

    class _A1PacketBody(SmartStructure):
        class _A1PacketHeader(SmartStructure):
            # A1Packet header fields
            _fields_ = [('PacketType', c_uint8),
                        ('_reserved', c_uint8)]
        # A1Packet body fields
        _fields_ = [('Header', _A1PacketHeader),
                    ('AddressType', c_uint8),
                    ('AddressSize', c_uint16)]

    def _opt_factory(self, body=None, address_field_len=0):
        if body is None:
            return Packet._EmptyBodyOpt()

        class _A1PacketBodyOpt(SmartStructure):
            # A1Packet opt/variable fields
            _fields_ = [('Address', c_uint8 * address_field_len)]
        return _A1PacketBodyOpt()

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = A1Packet._A1PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        self.data.AddressType = type(self).ADDRESS_TYPE_ANY
        self.data.AddressSize = 0
        if src_buf:
            self.from_bytes(src_buf)

    def from_bytes(self, src, validate=True):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=src, address_field_len=len(src)-5)
        self.opt.from_bytes(src[self.data.size:])
        if validate:
            self.validate()

    def validate(self):
        """Check packet for consistency. Raise BadPeer() inside if something is wrong"""
        super().validate()

        if self.data.AddressSize != len(self.opt.Address):
            raise BadPeer("AddressSize != len(Address)", self.data.AddressSize, len(self.opt.Address))
        if self.data.AddressSize > type(self).MAX_ADDRESS_LENGTH:
            raise BadPeer("Address too long: ", len(self.opt.Address))

        if self.data.AddressType == type(self).ADDRESS_TYPE_ANY:
            if self.data.AddressSize:
                raise BadPeer("Address must be empty for ADDRESS_TYPE_ANY type: ", self.data.AddressSize)
        elif self.data.AddressType == type(self).ADDRESS_TYPE_PUBKEY:
            if self.data.AddressSize != 32: # 32-byte public signing keys are defined in SaltCahnnel v2 specs
                raise BadPeer("Wrong AddressSize for ADDRESS_TYPE_PUBKEY: ", self.data.AddressSize)
        else:
            raise BadPeer("AddressType is unknown: ", self.data.AddressType)

    @property
    def Address(self):
        return bytes(self.opt.Address)

    @Address.setter
    def Address(self, value):
        self.opt = self._opt_factory(body=value, address_field_len=len(value))
        self.opt.Address = util.cbytes(value)


class A2Packet(Packet):
    TYPE = PacketType.TYPE_A2_PACKET.value
    P_SIZE = 10
    proto_pattern = re.compile(r'^[\w-./]+$')

    class _A2PacketBody(SmartStructure):
        class _A2PacketHeader(SmartStructure):
            # A2Packet header fields
            _fields_ = [('PacketType', c_uint8),
                        ('NoSuchServer', c_uint8, 1),
                        ('_reserved', c_uint8, 6),
                        ('LastFlag', c_uint8, 1)]

        # A2Packet body fields
        _fields_ = [('Header', _A2PacketHeader),
                    ('Count', c_int8)]

    def _opt_factory(self, body=None, prot_count=0):
        if body is None:
            return Packet._EmptyBodyOpt()

        class _A2Prot(SmartStructure):
            _fields_ = [("P1", c_uint8 * A2Packet.P_SIZE),
                       ("P2", c_uint8 * A2Packet.P_SIZE)]

        class _A2PacketBodyOpt(SmartStructure):
            # A2Packet opt/variable fields
            _fields_ = [('Prot', _A2Prot * prot_count)]

        return _A2PacketBodyOpt()

    def __init__(self, src_buf=None):
        super().__init__()
        self.data = A2Packet._A2PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        self.data.LastFlag = 1
        if src_buf:
            self.from_bytes(src_buf)

    def from_bytes(self, src, validate=True):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=src, prot_count=(len(src)-3)//(A2Packet.P_SIZE*2))
        self.opt.from_bytes(src[self.data.size:])
        if validate:
            self.validate()

    def _check_pstring(self, pstr):
        if len(pstr) != A2Packet.P_SIZE:
            return False
        return True if type(self).proto_pattern.match(pstr) else False

    def validate(self):
        """Check packet for consistency. Raise BadPeer() inside if something is wrong"""
        super().validate()

        if self.data.Header.NoSuchServer:
            if self.data.Count or len(self.opt.Prot):
                raise BadPeer("Count MUST be zero if NoSuchServer: ", self.data.Count)

        if not self.data.Header.LastFlag:
            raise BadPeer("LastFlag MUST be set for A2")

        if not 0 <= self.data.Count <=127:
            raise BadPeer("Count out of range")

        if len(self.opt.Prot) != self.data.Count:
            raise BadPeer("Prot array size doesn't match Count field value")

        for i, prot in self.opt.Prot:
            if not self._check_pstring(prot.P1):
                raise BadPeer("Invalid P1, Proto: ", i)
            if not self._check_pstring(prot.P2):
                raise BadPeer("Invalid P2, Proto: ", i)

    @property
    def Prot(self):
        return self.opt.Prot

    @Prot.setter
    def Prot(self, value):
        self.opt = self._opt_factory(body=value, prot_count=len(value))
        self.opt.Prot = value
