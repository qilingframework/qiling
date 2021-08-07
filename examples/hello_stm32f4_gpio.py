import sys
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def test_mcu_gpio_stm32f411():
    ql = Qiling(["../examples/rootfs/stm32f411/hex/hello_gpioA.hex"],                    
                archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DISASM)

    ql.hw.create('STM32F4xxUsart', 'usart2', (0x40004400, 0x40004800))
    ql.hw.create('STM32F4xxRcc', 'rcc', (0x40023800, 0x40023C00))
    ql.hw.create('STM32F4GPIO', 'gpioA', (0x40020000, 0x40020000 + 0x400))

    ql.hw.create_band_alias('sram', 0x20000000, 0x22000000, 0x2000000)
    ql.hw.create_band_alias('peripheral', 0x40000000, 0x42000000, 0x2000000)
    ql.run(count=1000)


if __name__ == "__main__":
    test_mcu_gpio_stm32f411()