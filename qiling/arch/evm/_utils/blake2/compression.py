import struct
from typing import (
    Tuple,
)

doc = """
    Lovingly lifted from https://github.com/buggywhip/blake2_py
    with this license:

      Copyright (c) 2009-2018 Larry Bugbee, Kent, WA, USA

      Permission to use, copy, modify, and/or distribute this software
      for any purpose with or without fee is hereby granted, provided
      that the above copyright notice and this permission notice appear
      in all copies.

      THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
      WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
      WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
      THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
      CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
      LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
      NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
      CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

        (the ISC license, a minor tweak of the BSD license)

"""


class Blake2:
    """ Blake2 is a base class for Blake2b and Blake2s """

    # for more than 10 rounds, the schedule wraps around to the beginning
    sigma_schedule = (
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )


class Blake2b(Blake2):

    WORDBITS = 64
    MASKBITS = 2 ** WORDBITS - 1
    WORDFMT = 'Q'

    IV = (
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    )

    ROT1 = 32
    ROT2 = 24
    ROT3 = 16
    ROT4 = 63


TMessageBlock = Tuple[int, int, int, int, int, int, int, int]


def blake2b_compress(
        num_rounds: int,
        h_starting_state: TMessageBlock,
        block: bytes,
        t_offset_counters: Tuple[int, int],
        final_block_flag: bool) -> bytes:
    """
    'F Compression' from section 3.2 of RFC 7693:
    https://tools.ietf.org/html/rfc7693#section-3.2
    """

    # Dereference these for [very small] speed improvement.
    # Perhaps more than anything, this makes the code
    # easier to read.
    MASKBITS = Blake2b.MASKBITS
    WORDBITS = Blake2b.WORDBITS
    IV = Blake2b.IV
    ROT1 = Blake2b.ROT1
    ROT2 = Blake2b.ROT2
    ROT3 = Blake2b.ROT3
    ROT4 = Blake2b.ROT4
    WB_ROT1 = WORDBITS - ROT1
    WB_ROT2 = WORDBITS - ROT2
    WB_ROT3 = WORDBITS - ROT3
    WB_ROT4 = WORDBITS - ROT4

    sigma_schedule = Blake2b.sigma_schedule
    sigma_schedule_len = len(sigma_schedule)

    # convert block (bytes) into 16 LE words
    m = struct.unpack_from('<16%s' % Blake2b.WORDFMT, bytes(block))

    v = [0] * 16
    v[0: 8] = h_starting_state
    v[8:12] = IV[:4]
    v[12] = t_offset_counters[0] ^ IV[4]
    v[13] = t_offset_counters[1] ^ IV[5]

    if final_block_flag:
        v[14] = Blake2b.MASKBITS ^ IV[6]
    else:
        v[14] = IV[6]

    # The original code had a mechanism to turn on a "tree mode",
    # setting f[1] to MASKBITS here.
    # There seems to be no reference to that bit flip in the 3.2 section of RFC 7693,
    # and there is no such setting in EIP-152. So the bit flip option is removed.
    v[15] = IV[7]

    # Within the confines of the Python language, this is a
    # highly optimized version of G().  It differs some from
    # the formal specification and reference implementation.
    def G(a: int, b: int, c: int, d: int) -> None:
        # dereference v[] for another small speed improvement
        va = v[a]
        vb = v[b]
        vc = v[c]
        vd = v[d]
        va = (va + vb + msri2) & MASKBITS
        w = vd ^ va
        vd = (w >> ROT1) | (w << (WB_ROT1)) & MASKBITS
        vc = (vc + vd) & MASKBITS
        w = vb ^ vc
        vb = (w >> ROT2) | (w << (WB_ROT2)) & MASKBITS
        va = (va + vb + msri21) & MASKBITS
        w = vd ^ va
        vd = (w >> ROT3) | (w << (WB_ROT3)) & MASKBITS
        vc = (vc + vd) & MASKBITS
        w = vb ^ vc
        vb = (w >> ROT4) | (w << (WB_ROT4)) & MASKBITS
        # re-reference v[]
        v[a] = va
        v[b] = vb
        v[c] = vc
        v[d] = vd

    # time to ChaCha
    for r in range(num_rounds):
        # resolve as much as possible outside G() and
        # don't pass as argument, let scope do its job.
        # Result is a 50% speed increase, but sadly,
        # "slow" divided by 1.5 is still "slow".  :-/
        sr = sigma_schedule[r % sigma_schedule_len]
        msri2 = m[sr[0]]
        msri21 = m[sr[1]]
        G(0, 4, 8, 12)
        msri2 = m[sr[2]]
        msri21 = m[sr[3]]
        G(1, 5, 9, 13)
        msri2 = m[sr[4]]
        msri21 = m[sr[5]]
        G(2, 6, 10, 14)
        msri2 = m[sr[6]]
        msri21 = m[sr[7]]
        G(3, 7, 11, 15)
        msri2 = m[sr[8]]
        msri21 = m[sr[9]]
        G(0, 5, 10, 15)
        msri2 = m[sr[10]]
        msri21 = m[sr[11]]
        G(1, 6, 11, 12)
        msri2 = m[sr[12]]
        msri21 = m[sr[13]]
        G(2, 7, 8, 13)
        msri2 = m[sr[14]]
        msri21 = m[sr[15]]
        G(3, 4, 9, 14)

    result_message_words = (h_starting_state[i] ^ v[i] ^ v[i + 8] for i in range(8))
    return struct.pack(f'<8{Blake2b.WORDFMT}', *result_message_words)
