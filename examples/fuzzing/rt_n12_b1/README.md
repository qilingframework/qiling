### Directions for using this example fuzzer

* Use `binwalk` to fully unpack the `.trx` firmware file hosted
 [here](https://www.asus.com/supportonly/rt-n12%20(ver.b1)/helpdesk_bios/).
Select `Driver & Utility` -> `BIOS & Firmware` and choose the latest version.

* Unpack the `.trx` file with `binwalk -eM` (install `sasquatch` before doing
so). Rename the resulting squashfs dir to `squashfs-root`.

* Ensure the `nvram` file provided is located in the same directory as the
fuzzer script.

* The path `/var/run/` must exist in the firmware's rootfs directory
and be writable. 

* In the `squashfs-root`,  copy the `httpd` binary from `usr/sbin/httpd` into
`www/`.

* Create a snapshot by running with the `--snapshot` arg. Visit 
`http://127.0.0.1:9000/www/FUZZME`. This is will create a snapshot file `httpd.bin`
to be used a starting point for fuzzing. The program will terminate after a
successful connection from a web browser.

* To fuzz, run ```afl-fuzz -i <input dir> -o <output dir> -x <optional but
 highly encouraged dict files from the internet> -U -- python3 fuzz.py --fuzz
--filename @@```

	- [Here's a good dictionary to
	 use](https://github.com/salmonx/dictionaries/blob/main/http.dict)

 	- Consider using the test cases in `http-input`

* Consult [AFL
  docs](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
on multicore, performance improvement, etc.


