"""A two-way, reliable communication channel.
Byte arrays can be read and written; a simple blocking model.
"""
import io
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
    def write(self, msg, *args, is_last=False):
        """Writes messages. This method may block."""
        pass


class StreamChannel(ByteChannel):
    """A ByteChannel implementation based on a pair of streams."""

    def __init__(self, in_stream, out_stream=None):
        if not out_stream:
            self.io = in_stream
        else:
            self.io = io.BufferedRWPair(in_stream, out_stream)

    def read(self):
        try:
           len_buf = self.io.read(4)
           if not len_buf:
               raise ComException("Unable to recv size prefix. NOT all requested data were obtained")
           msg_len = struct.unpack('<i', len_buf)
           msg = self.io.read(msg_len[0])
        except IOError as e:
            raise ComException(e)

    def write(self, message, *args, is_last=False):
        try:
            for msg in (message,) + args:
                mbytes = bytes(msg)
                self.io.write(struct.pack('<i', len(mbytes)))
                self.io.write(mbytes)
            self.io.flush()
        except IOError as e:
            raise ComException(e)


class SocketChannel(ByteChannel):
    def __init__(self, sock):
        #self.io = io.BufferedRWPair(sock.makefile('rb'), sock.makefile('wb'))
        self.sock = sock

    def read(self):
        try:
           #size_prefix = struct.unpack('<i', self.sock.recv(4))
           #if size_prefix[0] < 0:
           #    raise BadPeer("non-positive packet size, ", size_prefix[0])
           #return self.sock.recv(size_prefix[0])
           len_buf, success = self.recvall(4)
           if not success:
               raise ComException("Unable to recv size prefix. NOT all requested data were obtained")
           msg_len = struct.unpack('<i', len_buf)
           msg, success = self.recvall(msg_len[0])
           if not success:
               raise ComException("Unable to recv msg. NOT all requested data were obtained")
           return msg
        except Exception as e:
            raise ComException(e)

    def write(self, message, *args, is_last=False):
        raw = bytearray()
        try:
            for msg in (message,) + args:
                raw.extend(b''.join([struct.pack('<i', len(msg)), bytes(msg)]))
            self.sock.sendall(bytes(raw))
            # [TODO] do we need to close socket here if is_last == True ?
        except Exception as e:
            raise ComException(e)

    def recvall(self, count):
        buf = bytearray()
        while count:
            newbuf = self.sock.recv(count)
            if not newbuf: return (bytes(buf), False)
            buf.extend(newbuf)
            count -= len(newbuf)
        return (bytes(buf), True)


class PipeChannel(ByteChannel):
    """ByteChannel implementation based on 'multiprocessing' module's Pipes"""
    pass