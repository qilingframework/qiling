#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from abc import ABCMeta, abstractmethod
from qiling.const import *
from .const import *

class QlThread:
    __metaclass__=ABCMeta

    def __init__(self, ql):
        self.ql = ql
        self.thread_management = None
        self.log_file_fd = None
        self.stop_event = None

# the common functions which are used in qiling core.
# these functions must be implemented in child class.

# like pthread_self(), return the id of currunt thread.
#    @abstractmethod
    def get_id(self):
        pass

# like pthread_exit(), terminate current thread.
#    @abstractmethod
    def exit(self):
        pass

    @abstractmethod
    def stop(self):
        pass


class QlThreadManagement:
    def __init__(self, ql):
        self.ql = ql
        self.cur_thread = None
# threads list or dict?
        self.threads = None
