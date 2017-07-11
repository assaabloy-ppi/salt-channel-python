import saltchannel.exceptions


class SaltLibException(saltchannel.exceptions.SaltChannelException):
    """Base SaltLib exception."""

class NoSuchLibException(SaltLibException):
    """Thrown to indicate that no such library exists and is operational."""

class BadSignatureException(SaltLibException):
    """Thrown to indicate that a signature was not valid."""

class BadEncryptedDataException(SaltLibException):
    """Thrown to indicate that encrypted and authenticated data was not valid.
    The authentication tag (MAC) was invalid.
    """

