#!/bin/sh
AFL_AUTORESUME=1 AFL_PATH="/home/kabeor/Dev/qiling/examples/fuzzing/qnx_arm/AFLplusplus" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./fuzz_stm32f407.py @@