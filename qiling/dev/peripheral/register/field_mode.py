from enum import Enum


class FieldMode(Enum):
    Read = 1 << 0
    Write = 1 << 1
    Set = 1 << 2
    Toggle = 1 << 3
    WriteOneToClear = 1 << 4
    WriteZeroToClear = 1 << 5
    ReadToClear = 1 << 6

