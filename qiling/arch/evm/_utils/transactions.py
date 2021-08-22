#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import NamedTuple
from ..constants import CREATE_CONTRACT_ADDRESS


class IntrinsicGasSchedule(NamedTuple):
    gas_tx: int
    gas_txcreate: int
    gas_txdatazero: int
    gas_txdatanonzero: int


def calculate_intrinsic_gas(msg_data:bytes, msg_to, gas_schedule:IntrinsicGasSchedule) -> int:
    num_zero_bytes = msg_data.count(b'\x00')
    num_non_zero_bytes = len(msg_data) - num_zero_bytes
    if msg_to == CREATE_CONTRACT_ADDRESS:
        create_cost = gas_schedule.gas_txcreate
    else:
        create_cost = 0
    return (
        gas_schedule.gas_tx
        + num_zero_bytes * gas_schedule.gas_txdatazero
        + num_non_zero_bytes * gas_schedule.gas_txdatanonzero
        + create_cost
    )