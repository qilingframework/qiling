import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def stm32f4_led():
    ql = Qiling(["../rootfs/mcu/stm32f411/rand_blink.hex"],                    
                archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DISASM)

    # Set verbose=QL_VERBOSE.DEFAULT to find warning
    ql.run(count=1000)

if __name__ == "__main__":
    stm32f4_led()