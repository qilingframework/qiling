#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import copy
import logging
import os
import re
import weakref

from typing import Optional, TextIO

from qiling.const import QL_VERBOSE

QL_INSTANCE_ID = 114514

FMT_STR = '%(levelname)s\t%(message)s'

class COLOR:
    WHITE   = '\033[37m'
    CRIMSON = '\033[31m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    ENDC    = '\033[0m'

class QlBaseFormatter(logging.Formatter):
    __level_tag = {
        'WARNING'  : '[!]',
        'INFO'     : '[=]',
        'DEBUG'    : '[+]',
        'CRITICAL' : '[x]',
        'ERROR'    : '[x]'
    }

    def __init__(self, ql, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ql = weakref.proxy(ql)

    def get_level_tag(self, level: str) -> str:
        return self.__level_tag[level]

    def get_thread_tag(self, thread: str) -> str:
        return thread

    def format(self, record: logging.LogRecord):
        # In case we have multiple formatters, we have to keep a copy of the record.
        record = copy.copy(record)

        # early logging may access ql.os when it is not yet set
        try:
            cur_thread = self.ql.os.thread_management.cur_thread
        except AttributeError:
            tid = f''
        else:
            tid = self.get_thread_tag(str(cur_thread))

        level = self.get_level_tag(record.levelname)
        record.levelname = f'{level} {tid}'

        return super().format(record)

class QlColoredFormatter(QlBaseFormatter):
    __level_color = {
        'WARNING'  : COLOR.YELLOW,
        'INFO'     : COLOR.BLUE,
        'DEBUG'    : COLOR.MAGENTA,
        'CRITICAL' : COLOR.CRIMSON,
        'ERROR'    : COLOR.RED
    }

    def get_level_tag(self, level: str) -> str:
        s = super().get_level_tag(level)

        return f'{self.__level_color[level]}{s}{COLOR.ENDC}'

    def get_thread_tag(self, tid: str) -> str:
        s = super().get_thread_tag(tid)

        return f'{COLOR.GREEN}{s}{COLOR.ENDC}'

class RegexFilter(logging.Filter):
    def update_filter(self, regexp: str):
        self._filter = re.compile(regexp)

    def filter(self, record: logging.LogRecord):
        msg = record.getMessage()

        return self._filter.match(msg) is not None

def resolve_logger_level(verbose: QL_VERBOSE) -> int:
    return {
        QL_VERBOSE.DISABLED : logging.CRITICAL,
        QL_VERBOSE.OFF      : logging.WARNING,
        QL_VERBOSE.DEFAULT  : logging.INFO,
        QL_VERBOSE.DEBUG    : logging.DEBUG,
        QL_VERBOSE.DISASM   : logging.DEBUG,
        QL_VERBOSE.DUMP     : logging.DEBUG
    }[verbose]

def __is_color_terminal(stream: TextIO) -> bool:
    """Determine whether standard output is attached to a color terminal.

    see: https://stackoverflow.com/questions/53574442/how-to-reliably-test-color-capability-of-an-output-terminal-in-python3
    """

    def __handle_nt(fd: int) -> bool:
        import ctypes
        import msvcrt

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 4

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        hstdout = msvcrt.get_osfhandle(fd)
        mode = ctypes.c_ulong()

        return kernel32.GetConsoleMode(hstdout, ctypes.byref(mode)) and (mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0)

    def __handle_posix(fd: int) -> bool:
        import curses

        try:
            curses.setupterm(fd=fd)
        except curses.error:
            return True
        else:
            return curses.tigetnum('colors') > 0

    def __default(_: int) -> bool:
        return True

    handlers = {
        'nt'    : __handle_nt,
        'posix' : __handle_posix
    }

    handler = handlers.get(os.name, __default)

    return handler(stream.fileno())

def setup_logger(ql, log_file: Optional[str], console: bool, log_override: Optional[logging.Logger], log_plain: bool):
    global QL_INSTANCE_ID

    # If there is an override for our logger, then use it.
    if log_override is not None:
        log = log_override
    else:
        # We should leave the root logger untouched.
        log = logging.getLogger(f'qiling{QL_INSTANCE_ID}')
        QL_INSTANCE_ID += 1

        # Disable propagation to avoid duplicate output.
        log.propagate = False
        # Clear all handlers and filters.
        log.handlers = []
        log.filters = []

        # Do we have console output?
        if console:
            handler = logging.StreamHandler()

            if log_plain or not __is_color_terminal(handler.stream):
                formatter = QlBaseFormatter(ql, FMT_STR)
            else:
                formatter = QlColoredFormatter(ql, FMT_STR)

            handler.setFormatter(formatter)
            log.addHandler(handler)
        else:
            handler = logging.NullHandler()
            log.addHandler(handler)

        # Do we have to write log to a file?
        if log_file is not None:
            handler = logging.FileHandler(log_file)
            formatter = QlBaseFormatter(ql, FMT_STR)
            handler.setFormatter(formatter)
            log.addHandler(handler)

    log.setLevel(logging.INFO)

    return log

__all__ = ['RegexFilter', 'setup_logger', 'resolve_logger_level']
