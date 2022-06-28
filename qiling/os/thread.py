#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import abstractmethod
from gevent import Greenlet

from qiling import Qiling

class QlThread(Greenlet):

    def __init__(self, ql: Qiling):
        super().__init__()

        self.ql = ql
        self.log_file_fd = None

    def __str__(self) -> str:
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

