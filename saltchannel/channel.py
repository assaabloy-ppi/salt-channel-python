"""A two-way, reliable communication channel.
Byte arrays can be read and written; a simple blocking model.
"""
import io
import socket
import struct
from abc import ABCMeta, abstractmethod

from .exceptions import ComException, BadPeer

class ByteChannel(metaclass=ABCMeta):
    """Reads one message; blocks until one is available.
    """

    @abstractmethod
    def read(self):
        """Reads one message; blocks until one is available."""
        pass

    @abstractmethod
    def write(self, msg, *args):
        """Writes messages. This method may block."""
        pass


class StreamChannel(ByteChannel):
    """A ByteChannel implementation based on a pair of streams."""

    def __init__(self, in_stream, out_stream):
        self.io = io.BufferedRWPair(in_stream, out_stream)

    def read(self):
        try:
            size_prefix = struct.unpack('<i', self.io.read(size=4))
            if size_prefix < 0:
                raise BadPeer("non-positive packet size, ", size_prefix)
            return self.io.read(size=size_prefix)
        except IOError as e:
            raise ComException(e)

    def write(self, message, *args):
        try:
            for msg in message + args:
                mbytes = bytes(msg)
                self.io.write(struct.pack('<i', len(mbytes)))
                self.io.write(mbytes)
            self.io.flush()
        except IOError as e:
            raise ComException(e)


class SocketChannel(StreamChannel):
    def __init__(self, sock):
        self.io = io.BufferedRWPair(sock.makefile('rb', bufsize=0), sock.makefile('wb', bufsize=0))


class PipeChannel(ByteChannel):
    """ByteChannel implementation based on 'multiprocessing' module's Pipes"""
    raise NotImplementedError("PipeChannel is not implemented")