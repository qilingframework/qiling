from typing import (
    Tuple,
)

from eth_utils import (
    big_endian_to_int,
    int_to_big_endian,
)

from .. import constants

from .._utils.numeric import (
    get_highest_bit_index,
)
from .._utils.padding import (
    pad32r,
    zpad_right,
    zpad_left,
)

from ..vm.computation import (
    BaseComputation,
)


def _compute_adjusted_exponent_length(exponent_length: int,
                                      first_32_exponent_bytes: bytes) -> int:
    exponent = big_endian_to_int(first_32_exponent_bytes)

    if exponent_length <= 32 and exponent == 0:
        return 0
    elif exponent_length <= 32:
        return get_highest_bit_index(exponent)
    else:
        first_32_bytes_as_int = big_endian_to_int(first_32_exponent_bytes)
        return (
            8 * (exponent_length - 32)
            + get_highest_bit_index(first_32_bytes_as_int)
        )


def _compute_complexity(length: int) -> int:
    if length <= 64:
        return length ** 2
    elif length <= 1024:
        return (
            length ** 2 // 4 + 96 * length - 3072
        )
    else:
        return length ** 2 // 16 + 480 * length - 199680


def _extract_lengths(data: bytes) -> Tuple[int, int, int]:
    # extract argument lengths
    base_length_bytes = pad32r(data[:32])
    base_length = big_endian_to_int(base_length_bytes)

    exponent_length_bytes = pad32r(data[32:64])
    exponent_length = big_endian_to_int(exponent_length_bytes)

    modulus_length_bytes = pad32r(data[64:96])
    modulus_length = big_endian_to_int(modulus_length_bytes)

    return base_length, exponent_length, modulus_length


def _compute_modexp_gas_fee(data: bytes) -> int:
    base_length, exponent_length, modulus_length = _extract_lengths(data)

    first_32_exponent_bytes = zpad_right(
        data[96 + base_length:96 + base_length + exponent_length],
        to_size=min(exponent_length, 32),
    )[:32]
    adjusted_exponent_length = _compute_adjusted_exponent_length(
        exponent_length,
        first_32_exponent_bytes,
    )
    complexity = _compute_complexity(max(modulus_length, base_length))

    gas_fee = (
        complexity
        * max(adjusted_exponent_length, 1)
        // constants.GAS_MOD_EXP_QUADRATIC_DENOMINATOR
    )
    return gas_fee


def _modexp(data: bytes) -> int:
    base_length, exponent_length, modulus_length = _extract_lengths(data)

    if base_length == 0:
        return 0
    elif modulus_length == 0:
        return 0

    # compute start:end indexes
    base_end_idx = 96 + base_length
    exponent_end_idx = base_end_idx + exponent_length
    modulus_end_dx = exponent_end_idx + modulus_length

    # extract arguments
    modulus_bytes = zpad_right(
        data[exponent_end_idx:modulus_end_dx],
        to_size=modulus_length,
    )
    modulus = big_endian_to_int(modulus_bytes)
    if modulus == 0:
        return 0

    base_bytes = zpad_right(data[96:base_end_idx], to_size=base_length)
    base = big_endian_to_int(base_bytes)

    exponent_bytes = zpad_right(
        data[base_end_idx:exponent_end_idx],
        to_size=exponent_length,
    )
    exponent = big_endian_to_int(exponent_bytes)

    result = pow(base, exponent, modulus)

    return result


def modexp(computation: BaseComputation) -> BaseComputation:
    """
    https://github.com/ethereum/EIPs/pull/198
    """
    data = computation.msg.data_as_bytes

    gas_fee = _compute_modexp_gas_fee(data)
    computation.consume_gas(gas_fee, reason='MODEXP Precompile')

    result = _modexp(data)

    _, _, modulus_length = _extract_lengths(data)

    # Modulo 0 is undefined, return zero
    # https://math.stackexchange.com/questions/516251/why-is-n-mod-0-undefined
    result_bytes = b'' if modulus_length == 0 else zpad_left(
        int_to_big_endian(result),
        to_size=modulus_length
    )

    computation.output = result_bytes
    return computation
