import collections

#ticket - Ticket bytes received from the server.
#session_key - The session key, 32 bytes.
#session_nonce -  8-byte session nonce. Part of actual encrypt/decrypt nonce.
#   Guaranteed to be unique for every session with a particular
#   client-server-sessionKey tuple.
class ClientTicketData(collections.namedtuple('ClientTicketData', ['ticket', 'session_key', 'session_nonce'])):
    """Data that the client needs to store between sessions to use the resume feature."""
    __slots__ = ()