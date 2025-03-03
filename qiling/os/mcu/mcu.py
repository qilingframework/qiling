#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import TYPE_CHECKING
from unicorn import UC_ERR_OK, UcError

from qiling.const import QL_OS
from qiling.os.os import QlOs
from qiling.extensions.multitask import UnicornTask

if TYPE_CHECKING:
    from qiling import Qiling


class MCUTask(UnicornTask):

    def __init__(self, ql: 'Qiling', begin: int, end: int, task_id=None):
        super().__init__(ql.uc, begin, end, task_id)
        self.ql = ql

    def on_start(self):
        # Don't save anything.
        return None

    def on_interrupted(self, ucerr: int):
        self._begin = self.pc

        # And don't restore anything.
        if ucerr != UC_ERR_OK:
            raise UcError(ucerr)

        self.ql.hw.step()


class QlOsMcu(QlOs):
    type = QL_OS.MCU

    def __init__(self, ql: 'Qiling'):
        super().__init__(ql)
        self.runable = True
        self.fast_mode = False

    def stop(self):
        self.ql.emu_stop()
        self.runable = False

    def run(self):
        def current_pc() -> int:
            if hasattr(self.ql.arch, 'effective_pc'):
                return self.ql.arch.effective_pc

            return self.ql.arch.regs.arch_pc

        count = self.ql.count or 0
        end = self.ql.exit_point or -1
        timeout = self.ql.timeout or 0

        if self.fast_mode:
            if count != 0:
                self.ql.log.warning("`count` means 'Stop after sceduling *count* times' in fast mode.")

            task = MCUTask(self.ql, current_pc(), end)
            self.ql.uc.task_create(task)
            self.ql.uc.tasks_start(count=count, timeout=timeout)

        else:
            if timeout != 0:
                self.ql.log.warning("Timeout is not supported in non-fast mode.")

            self.runable = True
            self.counter = 0
            while self.runable:
                current_address = current_pc()

                if current_address == end:
                    break

                self.ql.emu_start(current_address, 0, count=1)
                self.ql.hw.step()

                self.counter += 1

                if count == self.counter:
                    break
