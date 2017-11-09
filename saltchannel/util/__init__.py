# -*- coding: utf-8 -*-

import ctypes
from abc import ABCMeta
import asyncio

def cbytes(src):
    """Convert bytes-like array to ctypes array of c_uint8."""
    #return (ctypes.c_uint8 * len(bytes(src)))(*list((bytes(src))))
    return (ctypes.c_uint8 * len(bytes(src))).from_buffer_copy(src)

def force_event_loop(loop=None):
    try:
        loop2 = loop or asyncio.get_event_loop()
    except RuntimeError:  # RuntimeError: There is no current event loop in thread 'Thread-x'.
        loop2 = asyncio.new_event_loop()
        asyncio.set_event_loop(loop2)
    return loop2


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class SingletonABCMeta(ABCMeta):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonABCMeta, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Syncizer(ABCMeta):
    """ A metaclass which adds synchronous version of coroutines.

    This metaclass finds all coroutine functions defined on a class
    and adds a synchronous version with a '_s' suffix appended to the
    original function name.
    """
    def __new__(cls, clsname, bases, dct, **kwargs):
        new_dct = {}
        for name,val in dct.items():
            # Make a sync version of all coroutine functions
            if asyncio.iscoroutinefunction(val):
                meth = cls.sync_maker(name)
                syncname = '{}_sync'.format(name)
                meth.__name__ = syncname
                meth.__qualname__ = '{}.{}'.format(clsname, syncname)
                new_dct[syncname] = meth
        dct.update(new_dct)
        return super().__new__(cls, clsname, bases, dct)

    @staticmethod
    def sync_maker(func):
        def sync_func(self, *args, **kwargs):
            meth = getattr(self, func)
            return self.loop.run_until_complete(meth(*args, **kwargs))
        return sync_func