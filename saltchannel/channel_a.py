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
    async def write(self, msg, *args, is_last=False):
        pass


class AsyncioChannel(ByteChannelA):

    def __init__(self, reader, writer):
        """ reader - instance of dev/client_server_a/SaltChannelStreamReader()
        writer - instance of dev/client_server_a/SaltChannelStreamWriter()"""
        self.reader = reader
        self.writer = writer

    async def read(self):
        return await self.reader.read_msg()

    async def write(self, msg, *args, is_last=False):
        for m in (msg,) + args:
            self.writer.write_msg(m)
        #[TODO] check : if (is_last)
        await self.writer.drain()

    def close(self):
        self.writer.close()


class AsyncizedChannel(ByteChannelA):
    """Used to wrap ByteChannel-based channel class to be instantly usable with await... """

    def __init__(self, channel):
        self.orig_channel = channel
        super(AsyncizedChannel, self).__init__()

    async def read(self):
        return self.orig_channel.read()

    async def write(self, msg, *args, is_last=False):
        self.orig_channel.write(msg, *args, is_last=is_last)