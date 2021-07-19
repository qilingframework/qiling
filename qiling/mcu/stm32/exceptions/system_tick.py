from qiling.mcu.mcu import QlMcu
from .exceptions import CoreException
from .const import ETYPE

class SystemTickException(CoreException):
    def __init__(self, mcu: QlMcu):
        super().__init__(mcu, 15, -1, ETYPE.SYSTICK, 0, 0x0000003C)
