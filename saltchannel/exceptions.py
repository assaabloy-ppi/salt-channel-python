
class SaltChannelException(RuntimeError):
    """Base SaltChannel exception."""


class ComException(SaltChannelException):
    """Communication exception. If data was successfully received, but not following spec, use BadPeer instead"""


class BadPeer(ComException):
    """Thrown to indicate that the peer send bad data, data that does not follow spec."""


class NoSuchServerException(ComException):
    """Thrown to indicate that the server with the given pubkey is not available."""

class TimeException(ComException):
    """Thrown to indicate that that a time delay was detected based in message timestamps."""


