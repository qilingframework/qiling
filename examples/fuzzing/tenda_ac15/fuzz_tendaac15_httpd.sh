#!/usr/bin/sh

AFL_DEBUG_CHILD_OUTPUT=1 AFL_AUTORESUME=1 AFL_PATH="$(realpath ./AFLplusplus)" PATH="$AFL_PATH:$PATH" ./AFLplusplus/afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./fuzz_tendaac15_httpd.py @@
