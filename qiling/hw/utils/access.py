#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum
from collections import deque
from typing import List


class Op(IntEnum):
    READ  = 0
    WRITE = 1


class Access:
    def __init__(self, op: Op, offset: int, value: int = 0):
        self.op = op
        self.offset = offset
        self.value = value

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, Access):
            return False

        if self.op != o.op or self.offset != o.offset:
            return False

        return True if self.op == Op.READ else self.value == o.value


class AccessSequence:
    def __init__(self, maxlen=2) -> None:
        self.deque = deque()
        self.maxlen = maxlen        

    def add(self, access: Access):
        self.deque.append(access)
        while len(self.deque) > self.maxlen:
            self.deque.popleft()

    def match(self, pattern: List[Access]) -> bool:
        if len(pattern) > len(self.deque):
            return False

        for i in range(-1, -len(pattern)-1, -1):
            if pattern[i] != self.deque[i]:
                return False

        return True
