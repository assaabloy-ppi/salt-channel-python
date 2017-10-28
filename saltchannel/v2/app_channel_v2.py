from ..channel import ByteChannel
from .packets import AppPacket


class AppChannelV2(ByteChannel):
    """An app message channel on top of an underlying ByteChannel (EncryptedChannelV2).
    Adds small header to messages."""

    def __init__(self, channel, time_keeper, time_checker):
        self.channel = channel
        self.time_keeper = time_keeper
        self.time_checker = time_checker
        self.buffered_m4 = None

    @property
    def last(self):
        return self.channel.last_flag

    def read(self):
        ap = AppPacket(src_buf=self.channel.read())
        self.time_checker.check_time(ap.data.Time)
        return ap.Data

    def write(self, message, *args, is_last=False):
        msg_list = []
        ap = AppPacket()

        if self.buffered_m4:
            self.buffered_m4.data.Time = self.time_keeper.get_time()
            msg_list.append(bytes(self.buffered_m4))
            self.buffered_m4 = None

        for msg in (message,) + args:
            ap.data.Time = self.time_keeper.get_time()
            ap.Data = msg
            msg_list.append(bytes(ap))

        self.channel.write(msg_list[0], *(msg_list[1:]), is_last=is_last)
