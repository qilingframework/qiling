#!/usr/bin/env python3

"""Simple example of how to use Qiling together with AFLplusplus.

Steps:
  o Clone and build AFL++
    $ git clone https://github.com/AFLplusplus/AFLplusplus.git
    $ make -C AFLplusplus

  o Build Unicorn support
    $ ( cd AFLplusplus/unicorn_mode ; ./build_unicorn_support.sh )

  o Start fuzzing
    $ AFL_AUTORESUME=1 AFL_PATH="$(realpath ./AFLplusplus)" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./fuzz_x8664_linux.py @@

  o Cleanup results
    $ rm -fr afl_outputs/default/
"""

import os
import sys

from typing import Sequence

QLHOME = os.path.realpath(r'../../..')

sys.path.append(QLHOME)
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe
from qiling.extensions import afl


def main(argv: Sequence[str], rootfs: str, infilename: str):
    # initialize a qiling instance.
    # note we keep verbosity off and thwart the program's output to gain some speed-up
    ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.OFF, console=False)

    # get the image base address
    img = ql.loader.get_image_by_name('x8664_fuzz')
    assert img is not None

    # fuzzing scope: the main function
    main_begins = img.base + 0x1275
    main_ends = img.base + 0x1293

    # redirect stdin to our mock to feed it with incoming fuzzed keystrokes
    ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())

    def place_input_callback(ql: Qiling, feed: bytes, round: int) -> bool:
        """Feed generated stimuli to the fuzzed target.

        This method is called with every fuzzing iteration.
        """

        # feed fuzzed input to our mock stdin
        ql.os.stdin.write(feed)

        # signal afl to proceed with this input
        return True

    def start_afl(ql: Qiling):
        """Have Unicorn fork and start instrumentation.
        """

        afl.ql_afl_fuzz(ql, infilename, place_input_callback, [main_ends])

    # set afl instrumentation [re]starting point
    ql.hook_address(start_afl, main_begins)

    def __crash(ql: Qiling) -> None:
        os.abort()

    # make the process crash whenever __stack_chk_fail@plt is about to be called.
    # this way afl will count stack protection violations as crashes
    ql.hook_address(__crash, img.base + 0x126e)

    # okay, ready to roll
    ql.run()

if __name__ == "__main__":
    main(
        rf'{QLHOME}/examples/fuzzing/linux_x8664/x8664_fuzz'.split(),
        rf'{QLHOME}/examples/rootfs/x8664_linux',
        rf'{QLHOME}/examples/fuzzing/linux_x8664/afl_inputs/a'
    )
