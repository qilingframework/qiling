# Qiling Unicornafl

"Load the cake and fuzz it too"

## Fuzz pretty much anything...

Just read on [the frontpage](../../README.md) what qiling can do, then think you can fuzz all of this with code coverage.


![Qilingfuzz Screenshopt, Around 160 execs per second and 13 crashes found..](qilingfzz.png)

## But How

[fuzz_x8664_linux.py](./fuzz_x8664_linux.py) is a simple example of how to use Qiling together with AFL.

It has been tested with the recent Qiling framework (the one you cloned), and [afl++](https://github.com/AFLplusplus/AFLplusplus)

Unicornafl adds methods to kick off the afl forkserver at any time to unicorn-engine.
*That means you can fuzz _any unicorn project_ (even c/rust/...) with a few lines of code.*

in this case, we make use of `afl_fuzz(..)`.

For this script, the fuzz method is started through a qiling callback on the `main()` method of the target binary.

Just look at the script, it is documented. ;)

## Try Out

This has been be, at some point, upstreamed to afl++ once it's ready, but for now, install afl++ and qiling, then this should install the bindings:

```bash
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd ./AFLplusplus
make binary-only
```

Then come back to this folder, and fuzz.

The easy way is to run `./fuzz.sh`.

To understand what the actual qiling code does, read through [the whole script](fuzz_x8664_linux.py), it should be documented well enough.

To trace bugs in the qiling script, either run it directly with an input file file, or run the fuzzer with `AFL_DEBUG_CHILD_OUTPUT=1 ./fuzz.sh`

## Debugging

If something goes wrong, you can do a few things:
- Run the script without AFL (`./fuzz_x8664_linx.py ./sominputfile` in our example).
- Sprinkle debug logs and hooks allover (for example, log the emulated instructions, `-t` in our example)
- For additional infos inside AFL ("did the python script crash?"), run with `AFL_DEBUG_CHILD_OUTPUT=1`.

To debug a crash, run the script without AFL. Crashes will be in `./afl_outputs/crashes`.

## Testemonials

"same effects of qemu-user with less speed" - [Andrea Fioraldi](https://twitter.com/andreafioraldi)

## Conclusion

Enjoy Fuzzing in Qiling.

Feel free to reach out [to me](https://twitter.com/domenuk) at any time :)
