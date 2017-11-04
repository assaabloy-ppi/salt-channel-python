import re

from saltchannel.util.packets import *
from ..exceptions import BadPeer as BadPeer


class A1Packet(Packet):
    TYPE = PacketType.TYPE_A1.value
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
    class Case(Enum):
        A2_NONE = 0
        A2_NO_SUCH_SERVER = 1
        A2_DEFAUT = 2

    TYPE = PacketType.TYPE_A2.value
    P_SIZE = 10
    SC2_PROT_STRING = b'SCv2------'
    UNSPECIFIED_PROT_STRING = b'----------'

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
            proto_re = re.compile(r'^[-./\w]+$')  # used for p-string validation

            def validate(self):
                if len(self.P1) != A2Packet.P_SIZE or len(self.P2) != A2Packet.P_SIZE:
                    return False
                return True if (type(self).proto_re.match(bytes(self.P1).decode()) and
                                type(self).proto_re.match(bytes(self.P2).decode())) else False

        class _A2PacketBodyOpt(SmartStructure):
            # A2Packet opt/variable fields
            _fields_ = [('Prot', _A2Prot * prot_count)]

        return _A2PacketBodyOpt()

    def __init__(self, src_buf=None, case=Case.A2_NONE):
        super().__init__()
        self.data = A2Packet._A2PacketBody()
        self.data.Header.PacketType = type(self).TYPE
        self.data.Count = 0
        self.data.Header.LastFlag = 1
        if case == self.Case.A2_NO_SUCH_SERVER:
            self.data.Header.NoSuchServer = 1
            return
        elif case == self.Case.A2_DEFAUT:
            self.data.Count = 1
            self.opt = self._opt_factory(body=self.data, prot_count=1)
            self.opt.Prot[0].P1 = util.cbytes(self.SC2_PROT_STRING)
            self.opt.Prot[0].P2 = util.cbytes(self.UNSPECIFIED_PROT_STRING)
            return
        if src_buf:
            self.from_bytes(src_buf)

    def from_bytes(self, src, validate=True):
        self.data.from_bytes(src)
        self.opt = self._opt_factory(body=src, prot_count=(len(src)-3)//(A2Packet.P_SIZE*2))
        self.opt.from_bytes(src[self.data.size:])
        if validate:
            self.validate()

    def validate(self):
        """Check packet for consistency. Raise BadPeer() inside if something is wrong"""
        super().validate()

        if self.data.Header.NoSuchServer:
            if self.data.Count or len(self.opt.Prot):
                raise BadPeer("Count MUST be zero if NoSuchServer: ", self.data.Count)

        if not self.data.Header.LastFlag:
            raise BadPeer("LastFlag MUST be set for A2")

        if not 0 <= self.data.Count <= 127:
            raise BadPeer("Count out of range")

        if len(self.opt.Prot) != self.data.Count:
            raise BadPeer("Prot array size doesn't match Count field value")

        for i, prot in enumerate(self.opt.Prot):
            if not prot.validate():
                raise BadPeer("Invalid P1, Proto: ", i)

    @property
    def Prot(self):
        return self.opt.Prot

    @Prot.setter
    def Prot(self, value):
        self.opt = self._opt_factory(body=value, prot_count=len(value))
        self.opt.Prot = value
