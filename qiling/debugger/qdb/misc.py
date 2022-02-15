#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable, Optional


class Breakpoint:
    """
    dummy class for breakpoint
    """
    def __init__(self, addr: int):
        self.addr = addr
        self.hitted = False


class TempBreakpoint(Breakpoint):
    """
    dummy class for temporay breakpoint
    """
    def __init__(self, addr: int):
        super().__init__(addr)


def read_int(s: str) -> int:
    """
    parse unsigned integer from string
    """
    return int(s, 0)


def parse_int(func: Callable) -> Callable:
    """
    function dectorator for parsing argument as integer
    """
    def wrap(qdb, s: str = "") -> int:
        assert type(s) is str
        try:
            ret = read_int(s)
        except:
            ret = None
        return func(qdb, ret)
    return wrap



if __name__ == "__main__":
    pass
