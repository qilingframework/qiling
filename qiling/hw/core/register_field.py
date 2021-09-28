from enum import Enum


class FieldMode(Enum):
    Read = 1 << 0
    Write = 1 << 1
    Set = 1 << 2
    Toggle = 1 << 3
    WriteOneToClear = 1 << 4
    WriteZeroToClear = 1 << 5
    ReadToClear = 1 << 6


class FieldModeUtils:
    def is_flag_set(flag:FieldMode, value:int):
        return (flag & value) != 0

    def is_readable(value:int):
        return (value & (FieldMode.Read | FieldMode.ReadToClear)) != 0

    def is_writable(value:int):
        return (value & (FieldMode.Write | FieldMode.Set | FieldMode.Toggle | FieldMode.WriteOneToClear | FieldMode.WriteZeroToClear)) != 0


class PeripheralRegisterField:
    def __init__(self, name, offset, width, access_mode=None) -> None:
        self.name = name
        self.offset = offset
        self.width = width
        self.access_mode = access_mode

