#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Mapping, Callable

from qiling import Qiling

from . import int10
from . import int13
from . import int15
from . import int16
from . import int19
from . import int1a
from . import int20
from . import int21

IntHandler = Callable[[Qiling], None]

# http://spike.scu.edu.au/~barry/interrupts.html
# http://www2.ift.ulaval.ca/~marchand/ift17583/dosints.pdf

handlers: Mapping[int, IntHandler] = {
	0x10: int10.handler,
	0x13: int13.handler,
	0x15: int15.handler,
	0x16: int16.handler,
	0x19: int19.handler,
	0x1a: int1a.handler,
	0x20: int20.handler,
	0x21: int21.handler
}

__all__ = ['handlers']
