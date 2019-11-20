# Qiling Unicornafl

"Load the cake and fuzz it too"

## Fuzz pretty much anything...

Just read on [the frontpage](../README.md) what qiling can do, then think you can fuzz all of this with code coverage.


![Qilingfuzz Screenshopt, Around 160 execs per second and 13 crashes found..](qilingfzz.png)

## But How

[fuzz_x8664_linux.py](./fuzz_x8664_linux.py) is a simple example of how to use Qiling together with AFL.

It has been tested with the recent Qiling framework (the one you cloned),
[afl++](https://github.com/vanhauser-thc/AFLplusplus)
and the [unicorn afl fork (WIP)](https://github.com/domenukk/unicorn/tree/0cd188142f52afce9f240eff92041947190e1174).

This unicorn fork adds methods to kick off the afl forkserver at any time.
*That means you can fuzz _any unicorn project_ (even c/rust/...) with a few lines of code.*

in this case, we make use of `afl_start_forkserver(..)`, although `afl_fuzz(..)` is even more powerful/faster 
(it can do persistent mode, so no more forking),
yet more work to implement. Blogpost or something else on this will follow.

For this script, the forkserver is added as a qiling callback on the `main()` method of the target binary.
On top, we add additional "crashes" (`os.abort`) as callback to the address where `stack-check fail` gets called.

Just look at the script, it is documented. ;)

## Try Out

This will be, at some point, upstreamed to afl++ once it's ready, but for now, install afl++ and qiling, then
```bash
git clone https://github.com/domenukk/unicorn.git
cd ./unicorn
git checkout 0cd188142f52afce9f240eff92041947190e1174
make -j8
cd ./bindings/python
./setup.py install --user
```

Then come back to this folder, and run `./fuzz.sh`.

Read through [the whole script](fuzz_x8664_linux.py), it should be documented well enough.

## Testemonials

"same effects of qemu-user with less speed" - [Andrea Fioraldi](https://twitter.com/andreafioraldi)

## Conclusion

Enjoy Fuzzing in Qiling.

Feel free to reach out [to me](https://twitter.com/domenuk) at any time :)
