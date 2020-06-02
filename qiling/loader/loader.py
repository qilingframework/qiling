#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import pefile
from qiling.const import QL_OS, QL_OS_ALL, QL_ARCH, QL_ENDIAN, QL_OUTPUT
from qiling.exception import QlErrorArch, QlErrorOsType, QlErrorOutput
from collections import namedtuple

class QlLoader():
    def __init__(self, ql):
        self.ql     = ql
        self.env    = self.ql.env
        self.images = []
        self.coverage_image = namedtuple('Image', 'base end path')
