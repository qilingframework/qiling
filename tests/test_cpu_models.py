#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import importlib
import unittest

from enum import Enum
from typing import Callable, Type

from qiling.arch.models import *


class CpuModelsTest(unittest.TestCase):
    """Make sure all *_CPU_MODEL enums are in sync with Unicorn's constants.
    """

    @staticmethod
    def __get_converter(ql_name: str) -> Callable[[str], str]:
        """Create a ql-name to uc-name convertion function.
        """

        def wrapped(k: str) -> str:
            arch, _, name = k.partition('_')

            return ql_name.format(arch=arch, name=name)

        return wrapped

    def __test_cpu_models(self, uc_const_module: str, ql_models_enum: Type[Enum], uc_name: str):
        ql_to_uc_name = self.__get_converter(uc_name)
        uc_consts = importlib.import_module(f'unicorn.{uc_const_module}').__dict__

        for k, v in ql_models_enum.__members__.items():
            uc_const_name = ql_to_uc_name(k)

            # make sure a ql enumeration entry has a cooresponding uc constant
            self.assertIn(uc_const_name, uc_consts, f'Could not find a matching constant for {k} ({uc_const_name})')

            # make sure their values are equal
            self.assertEqual(uc_consts[uc_const_name], v.value, f'Unexpected value for {uc_const_name}')

    def test_x86_cpu_models(self):
        self.__test_cpu_models('x86_const', X86_CPU_MODEL, 'UC_CPU_X86_{name}')

    def test_arm_cpu_models(self):
        self.__test_cpu_models('arm_const', ARM_CPU_MODEL, 'UC_CPU_ARM_{name}')

    def test_arm64_cpu_models(self):
        self.__test_cpu_models('arm64_const', ARM64_CPU_MODEL, 'UC_CPU_ARM64_{name}')

    def test_mips_cpu_models(self):
        self.__test_cpu_models('mips_const', MIPS_CPU_MODEL, 'UC_CPU_MIPS32_{name}')

    def test_ppc_cpu_models(self):
        self.__test_cpu_models('ppc_const', PPC_CPU_MODEL, 'UC_CPU_PPC32_{name}')

    def test_riscv_cpu_models(self):
        self.__test_cpu_models('riscv_const', RISCV_CPU_MODEL, 'UC_CPU_RISCV32_{name}')

    def test_riscv64_cpu_models(self):
        self.__test_cpu_models('riscv_const', RISCV64_CPU_MODEL, 'UC_CPU_RISCV64_{name}')


if __name__ == "__main__":
    unittest.main()
