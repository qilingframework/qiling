from .exceptions import CoreException
from .const import ETYPE

class SystemTickException(CoreException):
    def __init__(self, arch):
        super().__init__(arch, 15, -1, ETYPE.SYSTICK, 0, 0x0000003C)
