#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Optional
import platform

from qiling import utils
from qiling.const import QL_OS, QL_ARCH

class QlHost:
    """Interface to the hosting platform.
    """

    @cached_property
    def os(self) -> Optional[QL_OS]:
        """Hosting platform OS type.
        """

        system = platform.system()

        return utils.os_convert(system)

    @cached_property
    def arch(self) -> Optional[QL_ARCH]:
        """Hosting platform architecture type.
        """

        machine = platform.machine()

        return utils.arch_convert(machine)
