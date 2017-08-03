# -*- coding: utf-8 -*-

import ctypes
from abc import ABCMeta

def cbytes(src):
    """Convert bytes-like array to ctypes array of c_uint8."""
    return (ctypes.c_uint8 * len(bytes(src)))(*list((bytes(src))))

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