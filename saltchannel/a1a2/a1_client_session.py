from . import packets


class A1ClientSession:
    """"""
    def __init__(self, channel):
        self.channel = channel
        self.a1 = packets.A1Packet()
        self.a2 = None

    def do_a1a2(self):
        self.channel.write(bytes(self.a1))
        self.a2 = packets.A2Packet(src_buf=self.channel.read())
