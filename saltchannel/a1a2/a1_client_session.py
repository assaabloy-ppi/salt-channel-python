import asyncio
from . import packets


class A1ClientSession:
    """"""
    def __init__(self, channel, loop=None):
        self.loop = loop or asyncio.new_event_loop()

        self.channel = channel
        self.a1 = packets.A1Packet()
        self.a2 = None

    async def do_a1a2(self):
        await self.channel.write(bytes(self.a1))
        self.a2 = packets.A2Packet(src_buf=await self.channel.read())

    def do_a1a2_sync(self):
        self.channel.write_sync(bytes(self.a1))
        self.a2 = packets.A2Packet(src_buf=self.channel.read_sync())
