import copy
from typing import Dict

from eth_utils.toolz import (
    merge
)

from .... import (
    constants
)
from ....abc import OpcodeAPI
from ....vm import (
    mnemonics,
    opcode_values,
)
from ....vm.forks.byzantium.opcodes import (
    BYZANTIUM_OPCODES,
)
from ....vm.forks.petersburg.constants import (
    GAS_EXTCODEHASH_EIP1052
)
from ....vm.logic import (
    arithmetic,
    context,
    system,
)
from ....vm.opcode import (
    as_opcode
)


UPDATED_OPCODES = {
    opcode_values.SHL: as_opcode(
        logic_fn=arithmetic.shl,
        mnemonic=mnemonics.SHL,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SHR: as_opcode(
        logic_fn=arithmetic.shr,
        mnemonic=mnemonics.SHR,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SAR: as_opcode(
        logic_fn=arithmetic.sar,
        mnemonic=mnemonics.SAR,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.EXTCODEHASH: as_opcode(
        logic_fn=context.extcodehash,
        mnemonic=mnemonics.EXTCODEHASH,
        gas_cost=GAS_EXTCODEHASH_EIP1052,
    ),
    opcode_values.CREATE2: system.Create2.configure(
        __name__='opcode:CREATE2',
        mnemonic=mnemonics.CREATE2,
        gas_cost=constants.GAS_CREATE,
    )(),
}

PETERSBURG_OPCODES: Dict[int, OpcodeAPI] = merge(
    copy.deepcopy(BYZANTIUM_OPCODES),
    UPDATED_OPCODES,
)
