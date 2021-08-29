from typing import (
    cast,
    Iterable,
    Tuple,
)

from eth_utils import (
    to_int,
    to_tuple,
    ValidationError,
)

from .compression import (
    TMessageBlock,
)

TMessage = Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int, int, int]
TFCompressArgs = Tuple[int, TMessageBlock, TMessage, Tuple[int, int], bool]


def extract_blake2b_parameters(input_bytes: bytes) -> TFCompressArgs:
    num_bytes = len(input_bytes)
    if num_bytes != 213:
        raise ValidationError(
            f"input length for Blake2 F precompile should be exactly 213 bytes, got: {num_bytes}"
        )

    rounds = to_int(input_bytes[:4])

    h_state = cast(TMessageBlock, _get_64_bit_little_endian_words(input_bytes[4:68]))

    message = cast(TMessage, _get_64_bit_little_endian_words(input_bytes[68:196]))

    t_offset_counters = cast(Tuple[int, int], _get_64_bit_little_endian_words(input_bytes[196:212]))

    final_block_int = to_int(input_bytes[212])
    if final_block_int == 0:
        final_block_flag = False
    elif final_block_int == 1:
        final_block_flag = True
    else:
        raise ValidationError(
            f"incorrect final block indicator flag, needed 0 or 1, got: {final_block_int}"
        )

    return rounds, h_state, message, t_offset_counters, final_block_flag


@to_tuple
def _get_64_bit_little_endian_words(compact_bytes: bytes) -> Iterable[int]:
    remaining_bytes = compact_bytes
    if len(remaining_bytes) % 8 != 0:
        raise ValidationError(
            "Must send bytes in multiples of 8 to get 64-bit words, got length "
            f"{len(remaining_bytes)}"
        )

    while len(remaining_bytes):
        word, remaining_bytes = remaining_bytes[:8], remaining_bytes[8:]
        yield to_int(bytes(reversed(word)))
