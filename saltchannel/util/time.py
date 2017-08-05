from abc import ABCMeta, abstractmethod
from . import SingletonABCMeta
from ..exceptions import BadPeer


class TimeKeeper(metaclass=SingletonABCMeta):
    """Keeps time; relative time since first message sent. Measure in milliseconds."""

    """Call this first, must return 1 when timing is supported and 0 if not."""
    @abstractmethod
    def get_first_time(self): pass

    """Returns time in millis passed since get_first_time() was called or 0 if timing is not supported."""
    @abstractmethod
    def get_time(self): pass


class TimeChecker(metaclass=SingletonABCMeta):
    """"""

    """Reports first time. Should be 0 or 1."""
    @abstractmethod
    def report_first_time(self, time): pass

    """Checks 'time' against this object's clock."""
    @abstractmethod
    def check_time(self, time): pass


class NullTimeKeeper(TimeKeeper):
    """A TimeKeeper implementation that does not keep time.
    get_first_time() and get_time() always returns 0.
    """

    """Call this first, must return 1 when timing is supported and 0 if not."""
    def get_first_time(self):
        return 0

    """Returns time in millis passed since get_first_time() was called or 0 if timing is not supported."""
    def get_time(self):
        return 0


class NullTimeChecker(TimeChecker):
    """TimeChecker that accepts all time values."""

    """Reports first time. Should be 0 or 1."""
    def report_first_time(self, time):
        if time not in [0,1]:
            raise BadPeer("bad first time, " + time)

    """Checks 'time' against this object's clock."""
    def check_time(self, time): pass
