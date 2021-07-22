#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

class Peripheral:
    def __init__(self, core):
        self.core = core

    def step(self):
        raise NotImplementedError
