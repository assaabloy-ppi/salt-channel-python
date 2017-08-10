"""A two-way, reliable communication channel.
Byte arrays can be read and written; asyncio based implementation
"""

import io
import struct
from abc import ABCMeta, abstractmethod

from .exceptions import ComException, BadPeer
from saltchannel.dev.client_server_a import SaltChannelStreamReader,SaltChannelStreamWriter


class ByteChannelA(metaclass=ABCMeta):

    @abstractmethod
    async def read(self):
        pass

    @abstractmethod
    def write(self, msg, *args):
        """Writes messages. This method may block."""
        pass


class AsyncioChannel(ByteChannelA):

    def __init__(self, reader, writer):
        """ reader - instance of dev/client_server_a/SaltChannelStreamReader()
        writer - instance of dev/client_server_a/SaltChannelStreamWriter()"""
        self.reader = reader
        self.writer = writer

    async def read(self):
        return await self.reader.read_msg()

    async def write(self, msg, *args):
        for m in (msg,) + args:
            self.writer.write_msg(m)
        await self.writer.drain()

    async def close(self):
        self.writer.close()