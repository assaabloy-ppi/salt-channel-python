from collections import deque
from multiprocessing import Pipe
from saltchannel.channel import ByteChannel


class Tunnel:

    def __init__(self):
        self._q1 = deque()
        self._q2 = deque()
        self.channel1 = Tunnel._channel_factory(self._q1, self._q2)
        self.channel2 = Tunnel._channel_factory(self._q2, self._q1)

    @staticmethod
    def _channel_factory(in_queue, out_queue):
        class _Channel(ByteChannel):
            def read(self):
                return in_queue.popleft()

            def write(self, msg, *args):
                for m in msg + args:
                    out_queue.append(m)
        return _Channel()


class TunnelMP:
    def __init__(self):
        end1, end2 = Pipe()
        self.channel1 = TunnelMP._channel_factory(end1)
        self.channel2 = TunnelMP._channel_factory(end2)

    @staticmethod
    def _channel_factory(endpoint):
        class _Channel(ByteChannel):
            def read(self):
                return endpoint.recv_bytes()

            def write(self, msg, *args):
                for m in msg + args:
                    endpoint.send_bytes(m)
        return _Channel()