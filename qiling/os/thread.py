#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import ABCMeta, abstractmethod
from gevent import Greenlet
from qiling.const import *
from .const import *

class QlThread(Greenlet):
    __metaclass__=ABCMeta

    def __init__(self, ql):
        super(QlThread, self).__init__()
        self.ql = ql
        self.log_file_fd = None

    def __str__(self):
        return f"QlThread {self.get_id()}"

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

