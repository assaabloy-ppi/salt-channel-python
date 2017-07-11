"""A two-way, reliable communication channel.
Byte arrays can be read and written; a simple blocking model.
"""
from abc import ABCMeta, abstractmethod


class ByteChannel(metaclass=ABCMeta):
    """Reads one message; blocks until one is available.
    """

    @abstractmethod
    def read(self):
        """Reads one message; blocks until one is available."""
        pass

    @abstractmethod
    def write(self, *args, **kwargs):
        """Writes messages. This method may block."""
        pass