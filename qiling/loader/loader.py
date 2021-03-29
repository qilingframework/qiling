#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from collections import namedtuple

from qiling.const import QL_OS, QL_OS_ALL, QL_ARCH, QL_ENDIAN
from qiling.exception import QlErrorArch, QlErrorOsType, QlErrorOutput


class QlLoader():
    def __init__(self, ql):
        self.ql     = ql
        self.env    = self.ql.env
        self.argv   = self.ql.argv
        self.images = []
        self.coverage_image = namedtuple('Image', 'base end path')
        self.skip_exit_check = False
    
    def save(self):
        saved_state = {}
        saved_state['images'] = list(map(tuple, self.images))
        return saved_state

    def restore(self, saved_state):
        for (base, end, path) in saved_state['images']:
            self.images.append(self.coverage_image(base, end, path))

