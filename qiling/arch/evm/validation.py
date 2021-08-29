#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import functools

from typing import (
    Any,
    Dict,
    Iterable,
    Sequence,
    Union,
)

from eth_typing import (
    Address,
    Hash32,
)

from eth_utils import (
    ValidationError,
)
from eth_utils.toolz import dicttoolz
from eth_utils.toolz import functoolz
from eth_utils.toolz import itertoolz

from .constants import (
    GAS_LIMIT_ADJUSTMENT_FACTOR,
    GAS_LIMIT_MAXIMUM,
    GAS_LIMIT_MINIMUM,
    SECPK1_N,
    UINT_256_MAX,
    UINT_64_MAX,
)

from .typing import (
    BytesOrView,
)


def validate_is_bytes(value: bytes, title: str = "Value") -> None:
    if not isinstance(value, bytes):
        raise ValidationError(
            f"{title} must be a byte string.  Got: {type(value)}"
        )


def validate_is_bytes_or_view(value: BytesOrView, title: str = "Value") -> None:
    if isinstance(value, (bytes, memoryview)):
        return
    raise ValidationError(
        f"{title} must be bytes or memoryview. Got {type(value)}"
    )


def validate_is_integer(value: Union[int, bool], title: str = "Value") -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(
            f"{title} must be a an integer.  Got: {type(value)}"
        )


def validate_length(value: Sequence[Any], length: int, title: str = "Value") -> None:
    if not len(value) == length:
        raise ValidationError(
            f"{title} must be of length {length}.  Got {value} of length {len(value)}"
        )


def validate_length_lte(value: Sequence[Any], maximum_length: int, title: str = "Value") -> None:
    if len(value) > maximum_length:
        raise ValidationError(
            f"{title} must be of length less than or equal to {maximum_length}.  "
            f"Got {value} of length {len(value)}"
        )


def validate_gte(value: int, minimum: int, title: str = "Value") -> None:
    if value < minimum:
        raise ValidationError(
            f"{title} {value} is not greater than or equal to {minimum}"
        )
    validate_is_integer(value)


def validate_gt(value: int, minimum: int, title: str = "Value") -> None:
    if value <= minimum:
        raise ValidationError(
            f"{title} {value} is not greater than {minimum}"
        )
    validate_is_integer(value, title=title)


def validate_lte(value: int, maximum: int, title: str = "Value") -> None:
    if value > maximum:
        raise ValidationError(
            f"{title} {value} is not less than or equal to {maximum}"
        )
    validate_is_integer(value, title=title)


def validate_lt(value: int, maximum: int, title: str = "Value") -> None:
    if value >= maximum:
        raise ValidationError(
            f"{title} {value} is not less than {maximum}"
        )
    validate_is_integer(value, title=title)


def validate_canonical_address(value: Address, title: str = "Value") -> None:
    if not isinstance(value, bytes) or not len(value) == 20:
        raise ValidationError(
            f"{title} {value!r} is not a valid canonical address"
        )


def validate_multiple_of(value: int, multiple_of: int, title: str = "Value") -> None:
    if not value % multiple_of == 0:
        raise ValidationError(
            f"{title} {value} is not a multiple of {multiple_of}"
        )


def validate_is_boolean(value: bool, title: str = "Value") -> None:
    if not isinstance(value, bool):
        raise ValidationError(
            f"{title} must be an boolean.  Got type: {type(value)}"
        )


def validate_word(value: Hash32, title: str = "Value") -> None:
    if not isinstance(value, bytes):
        raise ValidationError(
            f"{title} is not a valid word. Must be of bytes type: Got: {type(value)}"
        )
    elif not len(value) == 32:
        raise ValidationError(
            f"{title} is not a valid word. Must be 32 bytes in length: Got: {len(value)}"
        )


def validate_uint64(value: int, title: str = "Value") -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(
            f"{title} must be an integer: Got: {type(value)}"
        )
    if value < 0:
        raise ValidationError(
            f"{title} cannot be negative: Got: {value}"
        )
    if value > UINT_64_MAX:
        raise ValidationError(
            f"{title} exeeds maximum UINT256 size.  Got: {value}"
        )


def validate_uint256(value: int, title: str = "Value") -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(
            f"{title} must be an integer: Got: {type(value)}"
        )
    if value < 0:
        raise ValidationError(
            f"{title} cannot be negative: Got: {value}"
        )
    if value > UINT_256_MAX:
        raise ValidationError(
            f"{title} exeeds maximum UINT256 size.  Got: {value}"
        )


def validate_stack_int(value: int) -> None:
    if 0 <= value <= UINT_256_MAX:
        return
    raise ValidationError(
        "Invalid Stack Item: Must be a 256 bit integer. Got {value!r}"
    )


def validate_stack_bytes(value: bytes) -> None:
    if len(value) <= 32:
        return
    raise ValidationError(
        "Invalid Stack Item: Must be either a length 32 byte string. Got {value!r}"
    )


validate_lt_secpk1n = functools.partial(validate_lte, maximum=SECPK1_N - 1)
validate_lt_secpk1n2 = functools.partial(validate_lte, maximum=SECPK1_N // 2 - 1)


def validate_unique(values: Iterable[Any], title: str = "Value") -> None:
    if not itertoolz.isdistinct(values):
        duplicates = functoolz.pipe(
            values,
            itertoolz.frequencies,  # get the frequencies

            # filter to ones that occure > 1
            functoolz.partial(dicttoolz.valfilter, lambda v: v > 1),
            sorted,  # sort them
            tuple,  # cast them to an immutiable form
        )
        raise ValidationError(
            f"{title} does not contain unique items.  Duplicates: "
            f"{', '.join((str(value) for value in duplicates))}"
        )


def validate_block_number(block_number: int, title: str = "Block Number") -> None:
    validate_is_integer(block_number, title)
    validate_gte(block_number, 0, title)


def validate_vm_block_numbers(vm_block_numbers: Iterable[int]) -> None:
    validate_unique(vm_block_numbers, title="Block Number set")

    for block_number in vm_block_numbers:
        validate_block_number(block_number)

def validate_gas_limit(gas_limit: int, parent_gas_limit: int) -> None:
    if gas_limit < GAS_LIMIT_MINIMUM:
        raise ValidationError(f"Gas limit {gas_limit} is below minimum {GAS_LIMIT_MINIMUM}")
    if gas_limit > GAS_LIMIT_MAXIMUM:
        raise ValidationError(f"Gas limit {gas_limit} is above maximum {GAS_LIMIT_MAXIMUM}")
    diff = gas_limit - parent_gas_limit
    if diff > (parent_gas_limit // GAS_LIMIT_ADJUSTMENT_FACTOR):
        raise ValidationError(
            f"Gas limit {gas_limit} difference to parent {parent_gas_limit} is too big {diff}"
        )


ALLOWED_HEADER_FIELDS = {
    'coinbase',
    'difficulty',
    'gas_limit',
    'timestamp',
    'extra_data',
    'mix_hash',
    'nonce',
    'uncles_hash',
    'transaction_root',
    'receipt_root',
}


def validate_header_params_for_configuration(header_params: Dict[str, Any]) -> None:
    extra_fields = set(header_params.keys()).difference(ALLOWED_HEADER_FIELDS)
    if extra_fields:
        raise ValidationError(
            "The `configure_header` method may only be used with the fields "
            f"({', '.join(tuple(sorted(ALLOWED_HEADER_FIELDS)))}). "
            f"The provided fields ({', '.join(tuple(sorted(extra_fields)))}) are not supported"
        )
