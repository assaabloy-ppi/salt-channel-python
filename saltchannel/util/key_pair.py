import collections

#Simple key pair class. Stores secret-public key pair as an named tuple for compactness.
class KeyPair(collections.namedtuple('KeyPair', ['sec', 'pub'])):
    __slots__ = ()

    def __str__(self):
        return ', \n'.join([self.sec.hex(), self.pub.hex()])
