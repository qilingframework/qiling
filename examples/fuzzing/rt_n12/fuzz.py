from qiling import *
from qiling.const import *
from qiling.extensions import afl
from typing import Optional
from qiling.os.const import *
from qiling.extensions.coverage import utils as cov_utils
import argparse

payload_location = 0 # location in snapshot to be modified

def my_send(ql:Qiling):
    """
    Hook to avoid writing to now no-longer connected socket
    used to create this snapshot
    """
    params = ql.os.resolve_fcall_params({'sockfd': INT,'buf':POINTER, 'len':SIZE_T, 'flags':INT })
    ql.log.info(buf)
    return

def fuzz(ql:Qiling, input_file):
    def place_input_callback(ql: Qiling, input: bytes, persistent_round: int) -> Optional[bool]:
        """Feed generated stimuli to the fuzzed target.

        This method is called with every fuzzing iteration.
        """
        
        if len(input)>=10000: # fgets() call uses 10000 for the size arg
            # so only size-1 bytes will actually be read
            return False
               
        ql.mem.write(payload_location, input)
    
        return True

    def start_afl(ql: Qiling):
        """Have Unicorn fork and start instrumentation.
        """
        avoids = []
        avoids.append(0x0040577c) # 501 not implemented, avoid wasting time
        # on non POST/HEAD/GET/etc requests
        avoids.append(0x00405b98) # jump back to select() loop?
        avoids.append(0x004059b4) # same as above?
        afl.ql_afl_fuzz(ql, input_file=input_file, place_input_callback=place_input_callback,   exits=avoids)
    ql.restore(snapshot="httpd.bin")
    global payload_location
    payload_location = ql.mem.search(b'GET /FUZZME HTTP/1.1')[0]
    ql.log.info("Location of input data")
    ql.log.info(hex(payload_location))
    ql.os.set_api('send', my_send, QL_INTERCEPT.CALL) # avoid crash due to the socket no longer being valid on clent end
    ql.hook_address(start_afl, 0x00404b20) # kick off from the start of snapshot
    ql.run(begin=0x00404b20)

def snapshot(ql:Qiling):
    '''
    Emulates the web server until right after the request is received
    Save state before any further parsing is done
    '''
    ql.run(end=0x00404b20)
    ql.save(reg=True, fd=True, mem=True, loader=True, os=True, cpu_context=True, snapshot="httpd.bin")

class Emulator:
    """
    ensure that httpd is copied from the regular
    location in usr/sbin/httpd
    """
    rootfs = "squashfs-root/"
    cmdline = "squashfs-root/www/httpd -p 9000".split()
    def fake_return(self):
        self.ql.arch.regs.pc = self.ql.arch.regs.read("RA")
    def my_nvram_get(self, ql:Qiling):
        self.ql.log.info("NVRAM get call")
        key_addr = self.ql.arch.regs.read("A0")
        key = str(ql.mem.string(key_addr))
        if self.dbg_level == QL_VERBOSE.DEBUG:
            self.ql.log.info('key ' + key)
        try:
            val = self.nvram[key]
        except Exception: # value not found, issue a blank one
            val = "" # if this causes logic issues later on, edit the nvram.txt file
        if self.dbg_level == QL_VERBOSE.DEBUG:
            self.ql.log.info('value ' + val)

        self.ql.mem.write(self.nvram_addr, bytes(val[::-1], 'utf-8'))
        self.ql.arch.regs.write("V0", self.nvram_addr)
        self.fake_return() # emulate return
        return
    def populate_nvram(self):
        f = open('nvram', 'rb')
        for line in f:
            data = line.strip(b'\n')
            pair = data.split(b'=')
            key = str(pair[0].decode('utf-8')) # should not fail, unless NVRAM file is corrupt
            if len(pair) != 2:
                val = ""
            else:
                val = str(pair[1].decode('utf-8'))
            self.nvram[key] = val

    def my_nvram_set(self,ql:Qiling):
        """
        hook to emulate writing to NVRAM
        """
        value = self.ql.mem.string(ql.arch.regs.read("A1"))
        key  = self.ql.mem.string(ql.arch.regs.read("A0"))
       
        self.nvram[value] = key
        if self.dbg_level == QL_VERBOSE.DEBUG:
            self.ql.log.info("Inside nvram set")
            self.ql.log.info(value)
            
            self.ql.log.info(key)
        self.fake_return()
        return
    def nvram_unset(self,ql:Qiling):
        """
        emulate clearing NVRAM
        """
        self.ql.log.info("fake unset")
        self.fake_return()
        return
    def my_nvram_get_int(self, ql:Qiling):
        """
        hook emulating return an integer from NVRAM
        """
        self.ql.log.info("NVRAM get_int call")
        key_addr = ql.arch.regs.read("A0")
        key = str(ql.mem.string(key_addr))
        val = self.nvram[key]
        if val != '':
            self.ql.arch.regs.write("V0", int(val, 16))
        else:
            self.ql.arch.regs.write("V0", 0x0)
        self.fake_return()
        return
    def add_hooks(self):
        """
        hook all meaningful NVRAM calls
        """
        self.ql.hook_address(self.my_nvram_get, 0x00420690)
        self.ql.hook_address(self.my_nvram_set, 0x004204b0)
        self.ql.hook_address(self.my_nvram_get_int, 0x004201b0)
        self.ql.hook_address(self.nvram_unset, 0x004206d0)
    def __init__(self, dbg_level):
        self.dbg_level = dbg_level
        self.ql = Qiling(self.cmdline,rootfs=self.rootfs, verbose=dbg_level)
        self.nvram = {}
        self.nvram_addr = self.ql.mem.map_anywhere(size=4096, info='nvram label')
        self.ql.fast_mode=True
        self.populate_nvram()
        self.add_hooks()
def main():
    parser = argparse.ArgumentParser(description='qiling example fuzzer for RT-N12 httpd binary')
    parser.add_argument('--snapshot', action='store_true')
    parser.add_argument('--fuzz', action='store_true')
    parser.add_argument('--dbg', action='store_true')
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--filename', action='store')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    emu = Emulator(QL_VERBOSE.OFF)
    if args.dbg:    
        emu.ql.debugger="qdb"
        
    if args.restore:
        emu.ql.restore(snapshot="httpd.bin")
    if args.snapshot:
        snapshot(emu.ql)
    if args.run:
        with cov_utils.collect_coverage(emu.ql, 'drcov', 'output.cov'):
            emu.ql.run()
    if args.fuzz and args.filename:
        fuzz(emu.ql, args.filename)
main()
