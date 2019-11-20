#!/usr/bin/sh
./afl-fuzz -i ./afl_inputs -o ./afl_outputs -U -- python3 ./fuzz_x8664_linux.py @@
