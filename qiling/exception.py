#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>
import sys, traceback

class QlErrorBase(Exception):
    def __init__(self, msg):
        super().__init__(self)
        self.msg = msg

    def __str__(self):
        return self.msg

class QlErrorFileNotFound(QlErrorBase):
    pass

class QlErrorOsType(QlErrorBase):
    pass

class QlErrorOutput(QlErrorBase):
    pass

class QlErrorArch(QlErrorBase):
    pass

class QlErrorRuntype(QlErrorBase):
    pass

class QlErrorJsonDecode(QlErrorBase):
    pass

class QlErrorNotImplemented(QlErrorBase):
    pass

class QlErrorELFFormat(QlErrorBase):
    pass

class QlErrorMACHOFormat(QlErrorBase):
    pass

def QlPrintException(msg):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print(msg + repr(traceback.format_tb(exc_traceback, limit=1) ) )
    