#!/usr/bin/env python3

"""Simple example of how to use QlFuzzer to easily create a custom fuzzer that
leverages Qiling and AFLplusplus.

Note: this example refers to linux_x8664/fuzz_x8664_linux.py

Steps:
  o Clone and build AFL++
    $ git clone https://github.com/AFLplusplus/AFLplusplus.git
    $ make -C AFLplusplus

  o Build Unicorn support
    $ ( cd AFLplusplus/unicorn_mode ; ./build_unicorn_support.sh )

  o Start fuzzing
    $ AFL_AUTORESUME=1 AFL_PATH="$(realpath ./AFLplusplus)" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./qlfuzzer_x8664_linux.py @@

  o Cleanup results
    $ rm -fr afl_outputs/default/
"""

from __future__ import annotations

import os
import sys

from typing import TYPE_CHECKING, Collection, Optional, Sequence

# replace this if qiling is located elsewhere
QLHOME = os.path.realpath(r'../../..')

sys.path.append(QLHOME)
from qiling.extensions import pipe
from qiling.extensions.afl.qlfuzzer import QlFuzzer


if TYPE_CHECKING:
    from qiling import Qiling


class MyFuzzer(QlFuzzer):
    """Custom fuzzer.
    """

    def setup(self, infilename: str, entry: int, exits: Collection[int], crashes: Optional[Collection[int]] = None) -> None:
        super().setup(infilename, entry, exits, crashes)

        # redirect stdin to our mock to feed it with incoming fuzzed keystrokes
        self.ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())

    def feed_input(self, ql: Qiling, stimuli: bytes, pround: int) -> bool:
        # feed fuzzed input as-is to our mock stdin
        ql.os.stdin.write(stimuli)

        # signal afl to proceed with this input
        return True


def main(argv: Sequence[str], rootfs: str, infilename: str):
    # initialize our custom fuzzer
    fuzzer = MyFuzzer(argv, rootfs)

    # calculate fuzzing scope effective addresses
    main_begins = fuzzer.ea(0x1275)
    main_ends = fuzzer.ea(0x1293)

    # make the process crash whenever __stack_chk_fail@plt is about to be called.
    # this way afl will count stack protection violations as fuzzing crashes
    stack_chk_fail = fuzzer.ea(0x126e)

    # set up fuzzing parameters
    fuzzer.setup(infilename, main_begins, [main_ends], [stack_chk_fail])

    # start fuzzing.
    #
    # note that although the main function is being fuzzed, we start emulating the program from its
    # default starting point to make sure 'main' has all the necessary data initialized and ready.
    fuzzer.run()


if __name__ == '__main__':
    main(
        rf'{QLHOME}/examples/fuzzing/linux_x8664/x8664_fuzz'.split(),
        rf'{QLHOME}/examples/rootfs/x8664_linux',
        rf'{QLHOME}/examples/fuzzing/linux_x8664/afl_inputs/a'
    )
