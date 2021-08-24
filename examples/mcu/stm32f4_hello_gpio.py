import sys
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def h_addr(ql, addr, data):
    print('---------------------')
    for i in range(0, 8):
        r = ql.reg.read('r'+str(i))
        print(f'r{str(i)} = {hex(r)}')
    print('---------------------')

def test_mcu_gpio_stm32f411():
    ql = Qiling(["../examples/rootfs/stm32f411/hex/hello_gpioA.hex"],                    
                archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEFAULT)

    ql.hw.create('STM32F4xxUsart', 'usart2', (0x40004400, 0x40004800))
    ql.hw.create('STM32F4xxRcc', 'rcc', (0x40023800, 0x40023C00))
    ql.hw.create('STM32F4xxGpio', 'gpioA', (0x40020000, 0x40020000 + 0x400), mode_reset=0x0C000000, ospeed_reset=0x0C000000, pupd_reset=0x64000000)

    # ql.hook_address(h_addr, 0x08000DB4)
    # ql.hook_code(h_addr, begin=0x08000DB4, end=0x8000DC2)

    ql.run(count=2745)


if __name__ == "__main__":
    test_mcu_gpio_stm32f411()