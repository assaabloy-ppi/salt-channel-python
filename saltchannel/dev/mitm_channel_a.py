from enum import Enum
import logging
import time
import codecs
from collections import deque, namedtuple
from saltchannel.channel_a import AsyncioChannel

class MitmEventType(Enum):
    """MITM event type"""
    UNKNOWN = 0
    READ = 1
    WRITE = 2
    WRITE_WITH_PREVIOUS = 3
    DELAY = 4


class MitmChannelA:
    """Man-in-the-Middle log/delay/manipulation class. Decorator pattern."""

    class LogRecord(namedtuple('LogRecord', ['time', 'type', 'data'])):
        __slots__ = ()

    def __init__(self, orig, log=None):
        self.orig = orig
        self.log = log
        self.queue = deque()
        self.time0 = 0
        self.log_buffering = False
        self.counter_read = 0
        self.counter_write = 0

    def flush_log_buffer(self):
        for item in self.queue:
            self._log_event(item, force_log=True)
        self.queue.clear()

    def _log_event(self, log_record, force_log=False):
        if not self.time0:
            self.time0 = log_record.time
        if force_log or not self.log_buffering:
            if self.log:
                self.log.info('{:0.6f} +{:0.6f}, {:s}, len(msg):{:d}, msg: b\'{:s}\''
                            .format(log_record.time, log_record.time-self.time0, log_record.type,
                                    len(log_record.data), log_record.data.hex()))
            else:
                self.queue.append(log_record)
        self.time0 = log_record.time

    async def read(self):
        data = await self.orig.read()
        self.counter_read += len(data)
        if self.log:
            self._log_event(MitmChannelA.LogRecord(time=time.perf_counter(), type=MitmEventType.READ, data=data))
        return data

    async def write(self, msg, *args):
        await self.orig.write(msg, *args)

        for m in (msg,) + args:
            self.counter_write += len(m)

        if self.log:
            self._log_event(MitmChannelA.LogRecord(time=time.perf_counter(), type=MitmEventType.WRITE, data=msg))
            for m in args:
                self._log_event(MitmChannelA.LogRecord(time=time.perf_counter(), type=MitmEventType.WRITE_WITH_PREVIOUS, data=m))

    def close(self):
        self.orig.close()


class AsyncizedMitmChannel(MitmChannelA):
    """TODO: Make it metaclass"""

    def __init__(self, orig, log=None):
        super(AsyncizedMitmChannel, self).__init__(orig, log)

    async def read(self):
        return self.orig.read()

    async def write(self, msg, *args):
        self.orig.write(msg, *args)