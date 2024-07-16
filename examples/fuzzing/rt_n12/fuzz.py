from qiling import *
from qiling.const import *
from qiling.extensions import afl
from typing import Optional
from qiling.os.const import *
from qiling.extensions.coverage import utils as cov_utils
import argparse

# From reversing the httpd binary, this is the first instruction
# after the fgets() call.
EMU_START = 0x00404B20


def my_send(ql: Qiling):
    """
    Hook to avoid writing to now no-longer connected socket
    used to create this snapshot
    """
    params = ql.os.resolve_fcall_params(
        {"sockfd": INT, "buf": POINTER, "len": SIZE_T, "flags": INT}
    )
    ql.log.info("Hooked send()")
    ql.log.info(params[buf])


def fuzz(ql: Qiling, input_file):
    def place_input_callback(
        ql: Qiling, input: bytes, persistent_round: int
    ) -> Optional[bool]:

        payload_location = 0  # location in snapshot to be modified
        # Feed generated stimuli to the fuzzed target.
        # This method is called with every fuzzing iteration.
        if len(input) >= 10000:  # fgets() call uses 10000 for the size arg
            # so only size-1 bytes will actually be read
            return False
        ql.mem.write(payload_location, input)
        return True

    def start_afl(ql: Qiling):
        """Have Unicorn fork and start instrumentation."""
        avoids = []
        # The avoids list is a set of addresses that we want Qiling to
        # stop at once hit. This way, we don't waste CPU cycles in areas
        # that aren't likely to be interesting.
        avoids = [
            0x0040577C,  # 501 not implemented, avoid wasting time on non POST/HEAD/GET/etc requests
            0x00405B98,  # jump back to select() loop?
            0x004059B4,  # same as above?
        ]
        afl.ql_afl_fuzz(
            ql,
            input_file=input_file,
            place_input_callback=place_input_callback,
            exits=avoids,
        )

    ql.restore(snapshot="httpd.bin")
    payload_location = ql.mem.search(b"GET /FUZZME HTTP/1.1")[0]
    ql.log.info(f"Location of input data: {payload_location:#010x}")
    ql.os.set_api(
        "send", my_send, QL_INTERCEPT.CALL
    )  # avoid crash due to the socket no longer being valid on clent end
    ql.hook_address(start_afl, EMU_START)
    # kick off from the start of snapshot
    ql.run(begin=EMU_START)


def snapshot(ql: Qiling):
    """
    Emulates the web server until right after the request is received
    Save state before any further parsing is done
    """
    ql.run(end=EMU_START)
    ql.save(
        reg=True,
        fd=True,
        mem=True,
        loader=True,
        os=True,
        cpu_context=True,
        snapshot="httpd.bin",
    )


class Emulator:
    """
    ensure that httpd is copied from the regular
    location in usr/sbin/httpd
    """

    rootfs = "squashfs-root/"
    cmdline = "squashfs-root/www/httpd -p 9000".split()

    def fake_return(self):
        self.ql.arch.regs.pc = self.ql.arch.regs.read("RA")

    def my_nvram_get(self, ql: Qiling):
        self.ql.log.info("NVRAM get call")
        key_addr = self.ql.arch.regs.read("A0")
        key = os.utils.read_cstring(key_addr)
        self.ql.log.debug(f"key: {key}")

        # Try/catch is used here in case an NVRAM value is missing
        # for some reason, to avoid an immediate crash
        try:
            val = self.nvram[key]
        except Exception:
            # value not found, issue a blank one
            val = ""  # if this causes logic issues later on,
        # edit the nvram.txt file
        self.ql.log.debug(f"value: {value}")

        # Need to use val[::-1] because of endianness
        # In this example, the target is MIPS32 LE
        self.ql.mem.write(self.nvram_addr, bytes(val[::-1], "utf-8"))
        self.ql.arch.regs.write("V0", self.nvram_addr)
        self.fake_return()  # emulate return
        return

    def populate_nvram(self):
        with open("nvram", "rb") as f:
            for line in f:
                data = line.strip(b"\n")
                pair = data.split(b"=")
                key = str(
                    pair[0].decode("utf-8")
                )  # should not fail, unless NVRAM file is corrupt
                if len(pair) != 2:
                    val = ""
                else:
                    val = str(pair[1].decode("utf-8"))
                self.nvram[key] = val

    def my_nvram_set(self, ql: Qiling):
        """
        hook to emulate writing to NVRAM
        """
        value = self.ql.mem.string(ql.arch.regs.read("A1"))
        key = self.ql.mem.string(ql.arch.regs.read("A0"))

        self.nvram[value] = key
        if self.dbg_level == QL_VERBOSE.DEBUG:
            self.ql.log.info("Inside nvram set")
            self.ql.log.info(value)

            self.ql.log.info(key)
        self.fake_return()
        return

    def nvram_unset(self, ql: Qiling):
        """
        emulate clearing NVRAM
        """
        self.ql.log.info("fake unset")
        self.fake_return()
        return

    def my_nvram_get_int(self, ql: Qiling):
        """
        hook emulating return an integer from NVRAM
        """
        self.ql.log.info("NVRAM get_int call")
        key_addr = ql.arch.regs.read("A0")
        key = str(ql.mem.string(key_addr))
        val = self.nvram[key]
        if val != "":
            self.ql.arch.regs.write("V0", int(val, 16))
        else:
            self.ql.arch.regs.write("V0", 0x0)
        self.fake_return()
        return

    def add_hooks(self):
        """
        hook all meaningful NVRAM calls
        Addresses were found by reversing the httpd binary
        """
        self.ql.hook_address(self.my_nvram_get, 0x00420690)
        self.ql.hook_address(self.my_nvram_set, 0x004204B0)
        self.ql.hook_address(self.my_nvram_get_int, 0x004201B0)
        self.ql.hook_address(self.nvram_unset, 0x004206D0)

    def __init__(self, dbg_level):
        self.dbg_level = dbg_level
        self.ql = Qiling(self.cmdline, rootfs=self.rootfs, verbose=dbg_level)
        self.nvram = {}  # dictionary to hold key-value pairs to emulate
        # NVRAM.
        self.nvram_addr = self.ql.mem.map_anywhere(size=4096, info="nvram label")
        # nvram_addr is a Qiling mapping designed to hold the contents of whatever NVRAM lookup we just performed.

        self.ql.fast_mode = True
        self.populate_nvram()
        self.add_hooks()


def main():
    parser = argparse.ArgumentParser(
        description="qiling example fuzzer for RT-N12 httpd binary"
    )
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--fuzz", action="store_true")
    parser.add_argument("--dbg", action="store_true")
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--filename", action="store")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    emu = Emulator(QL_VERBOSE.OFF)

    if args.run and args.fuzz:
        raise ValueError("Run and fuzz are mutually exclusive!")
    if args.dbg:
        emu.ql.debugger = "qdb"

    if args.restore:
        emu.ql.restore(snapshot="httpd.bin")
    if args.snapshot:
        snapshot(emu.ql)
    if args.run:
        with cov_utils.collect_coverage(emu.ql, "drcov", "output.cov"):
            emu.ql.run()
    if args.fuzz and args.filename:
        fuzz(emu.ql, args.filename)


main()
