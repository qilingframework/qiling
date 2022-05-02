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

# No more need for importing unicornafl, try afl.ql_afl_fuzz instead!

import os
import sys

from typing import Optional

sys.path.append("../../..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe
from qiling.extensions import afl

def main(input_file: str):
    ql = Qiling(["./x8664_fuzz"], "../../rootfs/x8664_linux",
        verbose=QL_VERBOSE.OFF, # keep qiling logging off
        console=False)          # thwart program output

    # redirect stdin to our mock to feed it with incoming fuzzed keystrokes
    ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())

    def place_input_callback(ql: Qiling, input: bytes, persistent_round: int) -> Optional[bool]:
        """Feed generated stimuli to the fuzzed target.

        This method is called with every fuzzing iteration.
        """

        # feed fuzzed input to our mock stdin
        ql.os.stdin.write(input)

        # signal afl to proceed with this input
        return True

    def start_afl(ql: Qiling):
        """Have Unicorn fork and start instrumentation.
        """

        afl.ql_afl_fuzz(ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    # get image base address
    ba = ql.loader.images[0].base

    # make the process crash whenever __stack_chk_fail@plt is about to be called.
    # this way afl will count stack protection violations as crashes
    ql.hook_address(callback=lambda x: os.abort(), address=ba + 0x126e)

    # set afl instrumentation [re]starting point. we set it to 'main'
    ql.hook_address(callback=start_afl, address=ba + 0x1275)

    # okay, ready to roll
    ql.run()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")

    main(sys.argv[1])
