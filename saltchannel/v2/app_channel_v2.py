from collections import deque

import saltchannel.util as util
from ..channel import ByteChannel
from .packets import PacketType, AppPacket, MultiAppPacket


class AppChannelV2(ByteChannel, metaclass=util.Syncizer):
    """An app message channel on top of an underlying ByteChannel (EncryptedChannelV2).
    Adds small header to messages.
    Asyncio-friendly implementation
    """
    def __init__(self, channel, time_keeper, time_checker, loop=None):
        super().__init__(loop=loop)
        self.channel = channel
        self.time_keeper = time_keeper
        self.time_checker = time_checker
        self.buffered_m4 = None
        self.readQ = deque()

    @property
    def last(self):
        return self.channel.last_flag

    async def read(self):
        if len(self.readQ):
            return self.readQ.popleft()

        raw_chunk = await self.channel.read()
        ap = AppPacket(src_buf=raw_chunk, validate=False)
        if ap.data.Header.PacketType == PacketType.TYPE_APP_PACKET.value:  # AppPacket detected
            ap.validate()
            self.time_checker.check_time(ap.data.Time)
            return ap.Data
        else:
            map = MultiAppPacket(src_buf=raw_chunk, validate=True)  # MultiAppPacket detected if no exception
            self.time_checker.check_time(map.data.Time)
            self.readQ.extend(map.opt.Message[1:])  # add all msgs but first to fifo (if more then one exists)
            return map.opt.Message[0]

    async def write(self, message, *args, is_last=False):
        msgs = (message,) + args
        current_time = self.time_keeper.get_time()
        rawmsg_list = []

        if self.buffered_m4:
            self.buffered_m4.data.Time = current_time
            rawmsg_list.append(bytes(self.buffered_m4))
            self.buffered_m4 = None

        if MultiAppPacket.should_use(msgs):
            map = MultiAppPacket()
            map.data.Time = current_time
            map.data.Count = len(msgs)
            map.create_opt_fields(msgs=msgs)
            rawmsg_list.append(bytes(map))
        else:
            ap = AppPacket()
            for msg in msgs:
                ap.data.Time = current_time
                ap.Data = msg
                rawmsg_list.append(bytes(ap))

        await self.channel.write(rawmsg_list[0], *(rawmsg_list[1:]), is_last=is_last)
