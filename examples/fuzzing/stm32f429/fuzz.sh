#!/bin/bash
AFL_AUTORESUME=1 afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./fuzz.py @@
