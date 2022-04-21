#!/bin/bash
AFL_AUTORESUME=1 afl-fuzz -i afl_inputs -o afl_outputs -t 2000 -U -- python3 ./fuzz.py @@
