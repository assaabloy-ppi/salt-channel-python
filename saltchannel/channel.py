"""A two-way, reliable communication channel.
Byte arrays can be read and written; asyncio based implementation
"""
import struct
import asyncio
from abc import ABCMeta, abstractmethod

import saltchannel.util as util
from .exceptions import ComException, BadPeer


class ByteChannel(metaclass=ABCMeta):

    def __init__(self, loop=None):
        self.loop = loop or asyncio.new_event_loop()

    @abstractmethod
    async def read(self):
        pass

    @abstractmethod
    async def write(self, msg, *args, is_last=False):
        pass

#    @abstractmethod
    def read_sync(self):
        pass

#    @abstractmethod
    def write_sync(self, msg, *args, is_last=False):
        pass


class AsyncioChannel(ByteChannel, metaclass=util.Syncizer):
    def __init__(self, reader, writer, loop=None):
        """
        reader - instance of dev/client_server_a/SaltChannelStreamReader()
        writer - instance of dev/client_server_a/SaltChannelStreamWriter()
        """
        super().__init__(loop=loop)
        self.reader = reader
        self.writer = writer

    async def read(self):
        return await self.reader.read_msg()

    async def write(self, msg, *args, is_last=False):
        for m in (msg,) + args:
            self.writer.write_msg(m)
        await self.writer.drain()

    def close(self):
        self.writer.close()


class SocketChannel(ByteChannel):
    def __init__(self, sock):
        self.sock = sock

    async def read(self):
        return self.read_sync()  # blocking version inside!

    async def write(self, msg, *args, is_last=False):
        self.write_sync(msg, *args, is_last=is_last)  # blocking version inside!

    def read_sync(self):
        try:
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

    def write_sync(self, message, *args, is_last=False):
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