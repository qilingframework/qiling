#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import sys

from typing import Any, Optional

sys.path.append("../../..")
from qiling.core import Qiling
from qiling.const import QL_VERBOSE

from qiling.extensions.afl import ql_afl_fuzz_custom
from qiling.extensions.mcu.stm32f4 import stm32f429

from unicorn import UC_ERR_OK, UcError

def main(input_file: str):
    ql = Qiling(["../../rootfs/mcu/stm32f429/bof.elf"], 
                archtype="cortex_m", 
                env=stm32f429, 
                ostype='mcu',
                verbose=QL_VERBOSE.DISABLED)

    ql.hw.create('rcc')
    ql.hw.create('usart2')
    ql.hw.create('usart3')
    
    ql.os.grain_size = 100
    ql.hook_code(lambda _x, _y, _z: ...)

    def place_input_callback(ql: Qiling, input_bytes: bytes, persistent_round: int) -> Optional[bool]:
        """Called with every newly generated input."""

        ql.hw.usart3.send(input_bytes)
        
        return True

    def fuzzing_callback(ql: Qiling):
        try:
            ql.run(count=40000)
        except:
            os.abort()

        return UC_ERR_OK

    ql.uc.ctl_exits_enabled(True)
    ql.uc.ctl_set_exits([0x80006d9])

    ql_afl_fuzz_custom(ql, input_file, place_input_callback, fuzzing_callback=fuzzing_callback)

    os.exit(0)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")

    main(sys.argv[1])