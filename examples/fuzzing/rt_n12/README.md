### Directions for using this example fuzzer

* Use `binwalk` to fully unpack the `.trx` firmware file provided.
Rename the unpacked squashfs to `squashfs-root`.


* Ensure the `nvram` file provided is located in the same directory as the
fuzzer script.

* The relative path `var/run/` must exist in the firmware's rootfs directory
and be writable. 

* In the `squashfs-root`,  copy the `httpd` binary from `usr/sbin/httpd` into `www/`.

* Create a snapshot by running with the `--snapshot` arg. Visit 
`127.0.0.1:9000/FUZZME`. This is will create a snapshot file `httpd.bin`
to be fuzzed with. The program will terminate after it finishes this.

* To fuzz, run ```afl-fuzz -i <input dir> -o <output dir> -x <dict files from internet> 
U -- python3 fuzz.py --fuzz --filename @@```

	- Consult [AFL docs](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
	on multicore, performance improvement, etc.


