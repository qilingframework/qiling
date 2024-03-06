#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import copy
import logging
import os
import re
import sys
import weakref

from typing import TYPE_CHECKING, Collection, IO, Optional, Protocol, Union, runtime_checkable
from logging import Filter, Formatter, LogRecord, Logger, NullHandler, StreamHandler, FileHandler

from qiling.const import QL_VERBOSE

if TYPE_CHECKING:
    from qiling import Qiling


QL_INSTANCE_ID = 114514

FMT_STR = '%(levelname)s\t%(message)s'


class COLOR:
    CRIMSON = '\033[31m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    DEFAULT = '\033[39m'


class QlBaseFormatter(Formatter):
    __level_tag = {
        'WARNING'  : '[!]',
        'INFO'     : '[=]',
        'DEBUG'    : '[+]',
        'CRITICAL' : '[x]',
        'ERROR'    : '[x]'
    }

    def __init__(self, ql: Qiling, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.ql: Qiling = weakref.proxy(ql)

    def get_level_tag(self, level: str) -> str:
        return self.__level_tag[level]

    def get_thread_tag(self, thread: str) -> str:
        return thread

    def format(self, record: LogRecord):
        # In case we have multiple formatters, we have to keep a copy of the record.
        record = copy.copy(record)

        # early logging may access ql.os when it is not yet set
        try:
            cur_thread = self.ql.os.thread_management.cur_thread
        except AttributeError:
            tid = ''
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

        return f'{self.__level_color[level]}{s}{COLOR.DEFAULT}'

    def get_thread_tag(self, thread: str) -> str:
        s = super().get_thread_tag(thread)

        return f'{COLOR.GREEN}{s}{COLOR.DEFAULT}'


class RegexFilter(Filter):
    def update_filter(self, regexp: str):
        self._filter = re.compile(regexp)

    def filter(self, record: LogRecord):
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


def __is_color_terminal(stream: IO) -> bool:
    """Determine whether a given device is attached to a color terminal.

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

    return stream.isatty() and handler(stream.fileno())


@runtime_checkable
class FileLike(Protocol):
    def isatty(self) -> bool: ...
    def fileno(self) -> int: ...


def setup_logger(ql: Qiling, logdevs: Collection[Union[IO, str]], plain: bool, override: Optional[Logger]):
    # if there is an override logger, use it as-is
    if override:
        log = override

    else:
        global QL_INSTANCE_ID

        # get our own logger and leave the root logger intact
        log = logging.getLogger(f'qiling{QL_INSTANCE_ID}')
        QL_INSTANCE_ID += 1

        # disable propagation to avoid duplicated output
        log.propagate = False

        # clear all existing handlers and filters, if any
        log.handlers.clear()
        log.filters.clear()

        if logdevs == []:
            handler = NullHandler()
            log.addHandler(handler)

        # adhere to the NO_COLOR convention (see: https://no-color.org/)
        no_color = os.getenv('NO_COLOR') or plain

        for dev in logdevs:
            if isinstance(dev, FileLike):
                handler = StreamHandler(dev)

            elif isinstance(dev, str):
                handler = FileHandler(dev)

            else:
                raise TypeError(f'unexpected logging device type: {type(dev).__name__}')

            if no_color or not __is_color_terminal(handler.stream):
                formatter = QlBaseFormatter(ql, FMT_STR)
            else:
                formatter = QlColoredFormatter(ql, FMT_STR)

            handler.setFormatter(formatter)
            log.addHandler(handler)

        # optimize logging speed by avoiding the collection of unnecesary logging properties
        logging._srcfile = None
        logging.logThreads = False
        logging.logProcesses = False
        logging.logMultiprocessing = False

    loglvl = resolve_logger_level(QL_VERBOSE.DEFAULT)
    log.setLevel(loglvl)

    return log


__all__ = ['RegexFilter', 'setup_logger', 'resolve_logger_level']
