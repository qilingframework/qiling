#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from .arch import Arch


class ArchRISCV(Arch):
    def __init__(self) -> None:
        regs = (
            'zero', 'ra', 'sp', 'gp', 'tp',
            't0', 't1', 't2', 's0', 's1',
            'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
            's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11',
            't3', 't4', 't5', 't6', 'pc'
        )

        aliases = {
            's0': 'fp'
        }

        super().__init__(regs, aliases, 4, 4)

    def unalias(self, name: str) -> str:
        if name.startswith('x') and name[1:].isdigit():
            idx = int(name[1:])

            xregs = (
                'zero', 'ra', 'sp', 'gp', 'tp',
                't0', 't1', 't2', 's0', 's1',
                'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
                's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11',
                't3', 't4', 't5', 't6'
            )

            if idx < len(xregs):
                return xregs[idx]

        return super().unalias(name)


class ArchRISCV64(ArchRISCV):
    def __init__(self) -> None:
        super().__init__()
        self._asize = 8
