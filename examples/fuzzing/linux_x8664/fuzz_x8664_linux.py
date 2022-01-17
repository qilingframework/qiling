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

from unicornafl import *
from unicorn import *

import os
import sys

from typing import Any, Optional

sys.path.append("../../..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

def main(input_file: str):
    mock_stdin = pipe.SimpleInStream(sys.stdin.fileno())

    ql = Qiling(["./x8664_fuzz"], "../../rootfs/x8664_linux",
            verbose=QL_VERBOSE.OFF, # keep qiling logging off
            console=False,          # thwart program output
            stdin=mock_stdin,       # redirect stdin to our mock to feed it with incoming fuzzed keystrokes
            stdout=None,
            stderr=None)

    def place_input_callback(uc: Uc, input: bytes, persistent_round: int, data: Any) -> Optional[bool]:
        """Called with every newly generated input.
        """

        ql.os.stdin.write(input)

    def start_afl(_ql: Qiling):
        """Callback from inside.
        """

        # We start our AFL forkserver or run once if AFL is not available.
        # This will only return after the fuzzing stopped.
        try:
            if not uc_afl_fuzz(_ql.uc, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point]):
                _ql.log.warning("Ran once without AFL attached")
                os._exit(0)

        except UcAflError as ex:
            # This hook triggers more than once in this example.
            # If this is the exception cause, we don't care.

            # TODO: choose a better hook position :)
            if ex.errno != UC_AFL_RET_CALLED_TWICE:
                raise

    # get image base address
    ba = ql.loader.images[0].base

    # make process crash whenever __stack_chk_fail@plt is about to be called.
    # this way afl will count stack protection violations as crashes
    ql.hook_address(callback=lambda x: os.abort(), address=ba + 0x1225)

    # set a hook on main() to let unicorn fork and start instrumentation
    ql.hook_address(callback=start_afl, address=ba + 0x122c)

    # okay, ready to roll
    ql.run()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")

    main(sys.argv[1])
