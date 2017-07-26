from enum import Enum
import logging
import time
import codecs
from collections import deque, namedtuple
from saltchannel.channel import ByteChannel

class MitmEventType(Enum):
    """MITM event type"""
    UNKNOWN = 0
    READ = 1
    WRITE = 2
    WRITE_WITH_PREVIOUS = 3
    DELAY = 4


class MitmChannel:
    """Man-in-the-Middle log/delay/manipulation class. Decorator pattern."""

    class LogRecord(namedtuple('LogRecord', ['time', 'type', 'data'])):
        __slots__ = ()

    def __init__(self, orig, log=None):
        self.orig = orig
        self.log = log
        self.queue = deque()
        self.time0 = 0
        self.log_buffering = False

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

    def read(self):
        data = self.orig.read()
        if self.log:
            self._log_event(MitmChannel.LogRecord(time=time.perf_counter(), type=MitmEventType.READ, data=data))
        return data

    def write(self, msg, *args):
        self.orig.write(msg, *args)
        if self.log:
            self._log_event(MitmChannel.LogRecord(time=time.perf_counter(), type=MitmEventType.WRITE, data=msg))
            for m in args:
                self._log_event(MitmChannel.LogRecord(time=time.perf_counter(), type=MitmEventType.WRITE_WITH_PREVIOUS, data=m))


