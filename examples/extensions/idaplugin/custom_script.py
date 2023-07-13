from future import __annotations__

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.core_hooks_types import HookRet


class QILING_IDA:

    def _show_context(self, ql: Qiling):
        registers = tuple(ql.arch.regs.register_mapping.keys())
        grouping = 4

        for idx in range(0, len(registers), grouping):
            ql.log.info('\t'.join(f'{r:5s}: {ql.arch.regs.read(r):016x}' for r in registers[idx:idx + grouping]))

    def custom_prepare(self, ql: Qiling) -> None:
        ql.log.info('Context before starting emulation:')
        self._show_context(ql)

    def custom_continue(self, ql: Qiling) -> List[HookRet]:
        ql.log.info('custom_continue hook')
        self._show_context(ql)

        return []

    def custom_step(self, ql: Qiling) -> List[HookRet]:
        def step_hook(ql: Qiling, addr: int, size: int):
            ql.log.info(f'Executing: {addr:#x}')
            self._show_context(ql)

        ql.log.info('custom_step hook')

        return [ql.hook_code(step_hook)]

    def custom_execute_selection(self, ql: Qiling) -> List[HookRet]:
        ql.log.info('custom_execute_selection hook')

        return []
