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

# This is new. Instead of unicorn, we import unicornafl. It's the same Uc with some new `afl_` functions
import unicornafl as UcAfl

# Make sure Qiling uses our patched unicorn instead of it's own, second so without instrumentation!
UcAfl.monkeypatch()

import os
import sys

from typing import Any, Optional

sys.path.append("../../..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.posix import stat

class MyPipe():
    """Fake stdin to handle incoming fuzzed keystrokes.
    """

    def __init__(self):
        self.buf = b''

    def write(self, s: bytes):
        self.buf += s

    def read(self, size: int) -> bytes:
        ret = self.buf[:size]
        self.buf = self.buf[size:]

        return ret

    def fileno(self) -> int:
        return 0

    def show(self):
        pass

    def clear(self):
        pass

    def flush(self):
        pass

    def close(self):
        self.outpipe.close()

    def lseek(self, offset: int, origin: int):
        pass

    def fstat(self):
        return stat.Fstat(self.fileno())

def main(input_file: str):
    stdin = MyPipe()

    ql = Qiling(["./x8664_fuzz"], "../../rootfs/x8664_linux",
            verbose=QL_VERBOSE.OFF, # keep qiling logging off
            console=False,          # thwart program output
            stdin=stdin,            # redirect stdin to our fake one
            stdout=None,
            stderr=None)

    def place_input_callback(uc: UcAfl.Uc, input: bytes, persistent_round: int, data: Any) -> Optional[bool]:
        """Called with every newly generated input.
        """

        stdin.write(input)

    def start_afl(_ql: Qiling):
        """Callback from inside.
        """

        # We start our AFL forkserver or run once if AFL is not available.
        # This will only return after the fuzzing stopped.
        try:
            if not _ql.uc.afl_fuzz(input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point]):
                _ql.log.warning("Ran once without AFL attached")
                os._exit(0)

        except UcAfl.UcAflError as ex:
            # This hook triggers more than once in this example.
            # If this is the exception cause, we don't care.

            # TODO: choose a better hook position :)
            if ex.errno != UcAfl.UC_AFL_RET_CALLED_TWICE:
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
