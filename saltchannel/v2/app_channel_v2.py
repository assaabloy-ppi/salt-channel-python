from channel import ByteChannel
from .packets import AppPacket


class AppChannelV2(ByteChannel):
    """An app message channel on top of an underlying ByteChannel (EncryptedChannelV2).
    Adds small header to messages."""

    def __init__(self, channel, time_keeper, time_checker):
        self.channel = channel
        self.time_keeper = time_keeper
        self.time_checker = time_checker
        self.buffered_m4 = None

    def read(self):
        ap = AppPacket(src_buf=self.channel.read())
        self.time_checker.check(ap.Time)
        return ap.Data

    def write(self, message, *args):
        raw = b''
        ap = AppPacket()

        if self.buffered_m4:
            self.buffered_m4.Time = self.time_keeper.get_time()
            raw = bytes(self.buffered_m4)

        for msg in (message,) + args:
            ap.Data = msg
            ap.Time = self.time_keeper.get_time()
            raw = raw.join(bytes(ap))

        self.channel.write(raw)
