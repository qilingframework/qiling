from ....exceptions import OutOfGas
from ....vm.computation import BaseComputation
from ....vm.forks.constantinople.storage import (
    GAS_SCHEDULE_EIP1283,
)
from ....vm.forks.istanbul import (
    constants
)
from ....vm.logic.storage import (
    net_sstore,
)

GAS_SCHEDULE_EIP2200 = GAS_SCHEDULE_EIP1283._replace(base=constants.GAS_SLOAD_EIP1884)


def sstore_eip2200(computation: BaseComputation) -> None:
    gas_remaining = computation.get_gas_remaining()
    if gas_remaining <= 2300:
        raise OutOfGas(
            "Net-metered SSTORE always fails below 2300 gas, per EIP-2200",
            gas_remaining,
        )
    else:
        return net_sstore(GAS_SCHEDULE_EIP2200, computation)
