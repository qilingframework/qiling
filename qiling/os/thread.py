#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from abc import   ABCMeta, abstractmethod

from qiling.const import *


THREAD_EVENT_INIT_VAL = 0
THREAD_EVENT_EXIT_EVENT = 1
THREAD_EVENT_UNEXECPT_EVENT = 2
THREAD_EVENT_EXECVE_EVENT = 3
THREAD_EVENT_CREATE_THREAD = 4
THREAD_EVENT_BLOCKING_EVENT = 5
THREAD_EVENT_EXIT_GROUP_EVENT = 6

THREAD_STATUS_RUNNING = 0
THREAD_STATUS_BLOCKING = 1
THREAD_STATUS_TERMINATED = 2
THREAD_STATUS_TIMEOUT = 3

class QlThread:
    __metaclass__=ABCMeta

    def __init__(self, ql):
        self.ql = ql
        self.thread_management = None
        self.log_file_fd = None
        self.stop_event = None

# the common functions which are used in qiling core.
# these functions must be implemented in child class.
    @abstractmethod
    def stop(self):
        pass


class QlThreadManagement:
    def __init__(self, ql):
        self.ql = ql
        self.cur_thread = None

