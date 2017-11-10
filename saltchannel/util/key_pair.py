import collections


class KeyPair(collections.namedtuple('KeyPair', ['sec', 'pub'])):
    """Simple key pair class. Stores secret-public key pair as an named tuple for compactness.
    """
    __slots__ = ()

    def __str__(self):
        return ', \n'.join([self.sec.hex(), self.pub.hex()])
