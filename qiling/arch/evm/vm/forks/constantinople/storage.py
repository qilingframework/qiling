from functools import partial

from ....vm.logic.storage import (
    net_sstore,
    NetSStoreGasSchedule,
)

GAS_SCHEDULE_EIP1283 = NetSStoreGasSchedule(
    base=200,
    create=20000,
    update=5000,
    remove_refund=15000,
)


sstore_eip1283 = partial(net_sstore, GAS_SCHEDULE_EIP1283)
