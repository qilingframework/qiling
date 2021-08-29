from typing import Tuple

from py_ecc import (
    optimized_bn128 as bn128,
)

from eth_utils import (
    big_endian_to_int,
    int_to_big_endian,
    ValidationError,
)
from eth_utils.toolz import (
    curry,
)

from .. import constants

from ..exceptions import (
    VMError,
)
from .._utils.bn128 import (
    validate_point,
)
from .._utils.padding import (
    pad32,
    pad32r,
)

from ..vm.computation import (
    BaseComputation,
)


@curry
def ecmul(
        computation: BaseComputation,
        gas_cost: int = constants.GAS_ECMUL) -> BaseComputation:

    computation.consume_gas(gas_cost, reason='ECMUL Precompile')

    try:
        result = _ecmull(computation.msg.data_as_bytes)
    except ValidationError:
        raise VMError("Invalid ECMUL parameters")

    result_x, result_y = result
    result_bytes = b''.join((
        pad32(int_to_big_endian(result_x.n)),
        pad32(int_to_big_endian(result_y.n)),
    ))
    computation.output = result_bytes
    return computation


def _ecmull(data: bytes) -> Tuple[bn128.FQ, bn128.FQ]:
    x_bytes = pad32r(data[:32])
    y_bytes = pad32r(data[32:64])
    m_bytes = pad32r(data[64:96])

    x = big_endian_to_int(x_bytes)
    y = big_endian_to_int(y_bytes)
    m = big_endian_to_int(m_bytes)

    p = validate_point(x, y)

    result = bn128.normalize(bn128.multiply(p, m))
    return result
