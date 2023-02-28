#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

import string

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

ROOTFS = r"rootfs/x86_linux"

class Solver:
    def __init__(self, invalid: bytes):
        # create a silent qiling instance
        self.ql = Qiling([rf"{ROOTFS}/bin/crackme_linux"], ROOTFS, verbose=QL_VERBOSE.OFF)

        self.ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())  # take over the input to the program using a fake stdin
        self.ql.os.stdout = pipe.NullOutStream(sys.stdout.fileno()) # disregard program output

        # execute program until it reaches the 'main' function
        self.ql.run(end=0x0804851b)

        # record replay starting and ending points.
        #
        # since the emulation halted upon entering 'main', its return address is there on
        # the stack. we use it to limit the emulation till function returns
        self.replay_starts = self.ql.arch.regs.arch_pc
        self.replay_ends = self.ql.stack_read(0)

        # instead of restarting the whole program every time a new flag character is guessed,
        # we will restore its state to the latest point possible, fast-forwarding a good
        # amount of start-up code that is not affected by the input.
        #
        # here we save the state just when 'main' is about to be called so we could use it
        # to jumpstart the initialization part and get to 'main' immediately
        self.jumpstart = self.ql.save() or {}

        # calibrate the replay instruction count by running the code with an invalid input
        # first. the instruction count returned from the calibration process will be then
        # used as a baseline for consequent replays
        self.best_icount = self.__run(invalid)

    def __run(self, input: bytes) -> int:
        icount = [0]

        def __count_instructions(ql: Qiling, address: int, size: int):
            icount[0] += 1

        # set a hook to fire up every time an instruction is about to execute
        hobj = self.ql.hook_code(__count_instructions)

        # feed stdin with input
        self.ql.os.stdin.write(input + b'\n')

        # resume emulation till function returns
        self.ql.run(begin=self.replay_starts, end=self.replay_ends)

        hobj.remove()

        return icount[0]

    def replay(self, input: bytes) -> bool:
        """Restore state and replay with a new input.

        Returns an indication to execution progress: `True` if a progress
        was made, `False` otherwise
        """

        # restore program's state back to the starting point
        self.ql.restore(self.jumpstart)

        # resume emulation and count emulated instructions
        curr_icount = self.__run(input)

        # the larger part of the input is correct, the more instructions are expected to be executed. this is true
        # for traditional loop-based validations like strcmp or memcmp which bails as soon as a mismatch is found:
        # more correct characters mean more loop iterations - thus more executed instructions.
        #
        # if we got a higher instruction count, it means we made a progress in the right direction
        if curr_icount > self.best_icount:
            self.best_icount = curr_icount

            return True

        return False

def progress(msg: str) -> None:
    print(msg, end='\r', file=sys.stderr, flush=True)

def main():
    flag = bytearray(b'*****')
    indices = (1, 4, 2, 0, 3)

    # all possible flag characters (may be reduced to uppercase and digits to save time)
    charset = string.printable

    progress('Initializing...')
    solver = Solver(flag)

    for i in indices:
        for ch in charset:
            flag[i] = ord(ch)

            progress(f'Guessing... {flag.decode()}')

            if solver.replay(flag):
                break

        else:
            raise RuntimeError('no match found')

    print(f'\nFlag found!')

if __name__ == "__main__":
    main()

# expected flag: L1NUX
