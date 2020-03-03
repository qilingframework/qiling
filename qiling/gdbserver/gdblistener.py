#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# gdbserver --remote-debug --disable-packet=threads,vCont 0.0.0.0:9999 /path/to binary
# documentation: according to https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol

import struct, os, re
from binascii import unhexlify

from qiling.gdbserver import qldbg
from qiling.gdbserver.reg_table import *

GDB_SIGNAL_TRAP = 5


def checksum(data):
    checksum = 0
    for c in data:
        if type(c) == str:
            checksum += (ord(c))
        else:
            checksum += c
    return checksum & 0xff


class GDBSession(object):
    """docstring for GDBSession"""
    def __init__(self, ql, clientsocket, exit_point, mappings):
        super(GDBSession, self).__init__()
        self.ql             = ql
        self.clientsocket   = clientsocket
        self.netin          = clientsocket.makefile('r')
        self.netout         = clientsocket.makefile('w')
        self.last_pkt       = None
        self.en_vcont       = False
        self.pc, self.sp    = self.ql.get_reg_spc()
        self.exe_abspath    = (os.path.abspath(self.ql.filename[0]))
        self.rootfs_abspath = (os.path.abspath(self.ql.rootfs))
        self.qldbg          = qldbg.Qldbg()
        self.qldbg.initialize(self.ql, exit_point=exit_point, mappings=mappings)
        if self.ql.ostype in (QL_LINUX, QL_FREEBSD):
            self.qldbg.bp_insert(self.ql.elf_entry)
        else:
            self.qldbg.bp_insert(self.ql.entry_point)

    

    def bin_to_escstr(self, rawbin):
        rawbin_escape = ""

        def incomplete_hex_check(hexchar):
            if len(hexchar) == 1:
                hexchar = "0" + hexchar
            return hexchar

        for a in rawbin:

            # The binary data representation uses 7d (ASCII ‘}’) as an escape character. 
            # Any escaped byte is transmitted as the escape character followed by the original character XORed with 0x20. 
            # For example, the byte 0x7d would be transmitted as the two bytes 0x7d 0x5d. The bytes 0x23 (ASCII ‘#’), 0x24 (ASCII ‘$’), and 0x7d (ASCII ‘}’) 
            # must always be escaped. Responses sent by the stub must also escape 0x2a (ASCII ‘*’), 
            # so that it is not interpreted as the start of a run-length encoded sequence (described next).

            if a in (42,35,36,125):
                a = a ^ 0x20
                a = (str(hex(a)[2:]))
                a = incomplete_hex_check(a)
                a = str("7d" + a)
            else:
                a = (str(hex(a)[2:]))
                a = incomplete_hex_check(a)

            rawbin_escape += a

        return unhexlify(rawbin_escape)

    def close(self):
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()

    def run(self):

        while self.receive() == 'Good':
            pkt = self.last_pkt
            self.send_raw('+')

            def handle_qmark(subcmd):
                #if self.ql.arch == QL_X8664:
                sp = self.ql.addr_to_str(self.ql.uc.reg_read(self.sp))
                pc = self.ql.addr_to_str(self.ql.uc.reg_read(self.pc))
                self.send('T0506:0*,;07:'+sp+';10:'+pc+';')


            def handle_c(subcmd):
                self.qldbg.resume_emu(self.ql.uc.reg_read(self.pc))
                self.send(('S%.2x' % GDB_SIGNAL_TRAP))


            handle_C = handle_c


            def handle_g(subcmd):
                s = ''
                if self.ql.arch == QL_X86:
                    for reg in registers_x86[:17]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = self.ql.addr_to_str(r)
                        s += tmp

                if self.ql.arch == QL_X8664:
                    for reg in registers_x8664[:17]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = self.ql.addr_to_str(r)
                        s += tmp
                    for reg in registers_x8664[17:24]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = self.ql.addr_to_str(r, short = True)
                        s += tmp
                
                if self.ql.arch == QL_ARM:
                    for reg in registers_arm[:17]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = self.ql.addr_to_str(r)
                        s += tmp
                
                self.send(s)


            def handle_G(subcmd):
                count = 0
                if self.ql.arch == QL_X86:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i+7]
                        reg_data = int(reg_data, 16)
                        self.ql.uc.reg_write(registers_x86[count], reg_data)
                        count += 1

                elif self.ql.arch == QL_X8664:
                    for i in range(0, 17*16, 16):
                        reg_data = subcmd[i:i+15]
                        reg_data = int(reg_data, 16)
                        self.ql.uc.reg_write(registers_x86[count], reg_data)
                        count += 1
                    for j in range(17*16, 17*16+15*8, 8):
                        reg_data = subcmd[j:j+7]
                        reg_data = int(reg_data, 16)
                        self.ql.uc.reg_write(registers_x86[count], reg_data)
                        count += 1
                
                elif self.ql.arch == QL_ARM:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i + 7]
                        reg_data = int(reg_data, 16)
                        self.ql.uc.reg_write(registers_arm[count], reg_data)
                        count += 1
                
                self.send('OK')


            def handle_H(subcmd):
                if subcmd.startswith('g'):
                    self.send('OK')
                if subcmd.startswith('c'):
                    self.send('OK')


            def handle_m(subcmd):
                addr, size = subcmd.split(',')
                addr = int(addr, 16)
                size = int(size, 16)

                try:
                    tmp = ''
                    for s in range(size):
                        mem = self.ql.uc.mem_read(addr + s, 1)
                        mem = "".join(
                            [str("{:02x}".format(ord(c))) for c in mem.decode('latin1')])
                        tmp += mem
                    self.send(tmp)

                except:
                    self.send('E14')


            def handle_M(subcmd):
                addr, data = subcmd.split(',')
                size, data = data.split(':')
                addr = int(addr, 16)
                data = int(data, 16)
                try:
                    self.ql.mem_write(addr, data)
                    self.send('OK')
                except:
                    self.send('E01')


            def handle_p(subcmd):
                reg_index = int(subcmd, 16)
                reg_value = None
                try:
                    if self.ql.arch == QL_X86:
                        if reg_index <= 24:
                            reg_value = self.ql.uc.reg_read(registers_x86[reg_index-1])
                        else:
                            reg_value = 0
                        reg_value = self.ql.addr_to_str(reg_value)
                    
                    if self.ql.arch == QL_X8664:
                        if reg_index <= 32:
                            reg_value = self.ql.uc.reg_read(registers_x8664[reg_index-1])
                        else:
                            reg_value = 0
                        if reg_index <= 17:
                            reg_value = self.ql.addr_to_str(reg_value)
                        elif 17 < reg_index:
                            reg_value = self.ql.addr_to_str(reg_value, short = True)
                    
                    if self.ql.arch == QL_ARM:
                        if reg_index < 17:
                            reg_value = self.ql.uc.reg_read(registers_arm[reg_index - 1])
                        else:
                            reg_value = 0
                        reg_value = self.ql.addr_to_str(reg_value)

                    self.send(reg_value)
                except:
                    self.close()
                    raise


            def handle_P(subcmd):
                reg_index, reg_data = subcmd.split('=')
                reg_index = int(reg_index, 16)
                if self.ql.arch == QL_X86:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.uc.reg_write(registers_x86[reg_index], reg_data)
                
                if self.ql.arch == QL_X8664:
                    if reg_index <= 17:
                        reg_data = int(reg_data, 16)
                        reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                        self.ql.uc.reg_write(registers_x8664[reg_index], reg_data)
                    else:
                        reg_data = int(reg_data[:8], 16)
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                        self.ql.uc.reg_write(registers_x8664[reg_index], reg_data)
                
                if self.ql.arch == QL_ARM:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.uc.reg_write(registers_arm[reg_index], reg_data)
                
                self.ql.nprint("gdb> write to register %x with %x" % (registers_x8664[reg_index], reg_data))
                self.send('OK')


            def handle_Q(subcmd):
                if subcmd.startswith('StartNoAckMode'):
                    self.send('OK')

                elif subcmd.startswith('DisableRandomization'):
                    self.send('OK')

                elif subcmd.startswith('ProgramSignals'):
                    self.send('OK')

                elif subcmd.startswith('NonStop'):
                    self.send('OK')

                elif subcmd.startswith('PassSignals'):
                    self.send('OK')

            def handle_D(subcmd):
                self.send('OK')

            def handle_q(subcmd):
                if subcmd.startswith('Supported:'):
                    if self.ql.multithread == False:
                        if self.ql.arch in (QL_X86, QL_X8664):
                            self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")
                        elif self.ql.arch == QL_ARM:
                            self.send  ('PacketSize=3fff;QPassSignals+;QProgramSignals+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+')    

                elif subcmd.startswith('Xfer:features:read'):
                    xfercmd_file = subcmd.split(':')[3]
                    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
                    
                    if self.ql.arch == QL_X8664:
                        xfercmd_file = os.path.join(ROOT_DIR,"xml","x8664", xfercmd_file)
                    elif self.ql.arch == QL_ARM:
                        print("arm")
                        xfercmd_file = os.path.join(ROOT_DIR,"xml","arm", xfercmd_file)
                    else:    
                        self.ql.nprint("gdb> arch file not found: %s" % (xfercmd_file))
                        exit(1)

                    if os.path.exists(xfercmd_file):
                        f = open(xfercmd_file, 'r')
                        file_contents = f.read()
                        self.send("l" + file_contents)
                    else:
                        self.ql.nprint("gdb> xml file not found: %s" % (xfercmd_file))
                        exit(1)

                elif subcmd.startswith('Xfer:threads:read::0,'):
                    file_contents = ("<threads>\r\n<thread id=\"2048\" core=\"3\" name=\"" + str(self.ql.filename[0].split('/')[-1]) + "\"/>\r\n</threads>")
                    self.send("l" + file_contents)

                elif subcmd.startswith('Xfer:auxv:read::'):
                    if self.ql.ostype in (QL_LINUX, QL_FREEBSD):
                        if self.ql.archbit == 64:
                            ANNEX               = "00000000000000"
                            AT_SYSINFO_EHDR     = "0000000000000000" # System-supplied DSO's ELF header
                            ID_AT_HWCAP         = "1000000000000000"
                            ID_AT_PAGESZ        = "0600000000000000"
                            ID_AT_CLKTCK        = "1100000000000000"
                            AT_CLKTCK           = "6400000000000000" # Frequency of times() 100
                            ID_AT_PHDR          = "0300000000000000"
                            ID_AT_PHENT         = "0400000000000000"
                            ID_AT_PHNUM         = "0500000000000000"
                            ID_AT_BASE          = "0700000000000000"
                            ID_AT_FLAGS         = "0800000000000000"
                            ID_AT_ENTRY         = "0900000000000000"
                            ID_AT_UID           = "0b00000000000000"
                            ID_AT_EUID          = "0c00000000000000"
                            ID_AT_GID           = "0d00000000000000"
                            ID_AT_EGID          = "0e00000000000000"
                            ID_AT_SECURE        = "1700000000000000"
                            AT_SECURE           = "0000000000000000"
                            ID_AT_RANDOM        = "1900000000000000"
                            ID_AT_HWCAP2        = "1a00000000000000"
                            AT_HWCAP2           = "0000000000000000"
                            ID_AT_EXECFN        = "1f00000000000000"
                            AT_EXECFN           = "0000000000000000" # File name of executable
                            ID_AT_PLATFORM      = "f000000000000000"
                            ID_AT_NULL          = "0000000000000000"
                            AT_NULL             = "0000000000000000"

                        elif self.ql.archbit == 32:
                            ANNEX           = "000000"
                            AT_SYSINFO_EHDR = "00000000"  # System-supplied DSO's ELF header
                            ID_AT_HWCAP     = "10000000"
                            ID_AT_PAGESZ    = "06000000"
                            ID_AT_CLKTCK    = "11000000"
                            AT_CLKTCK       = "64000000"  # Frequency of times() 100
                            ID_AT_PHDR      = "03000000"
                            ID_AT_PHENT     = "04000000"
                            ID_AT_PHNUM     = "05000000"
                            ID_AT_BASE      = "07000000"
                            ID_AT_FLAGS     = "08000000"
                            ID_AT_ENTRY     = "09000000"
                            ID_AT_UID       = "0b000000"
                            ID_AT_EUID      = "0c000000"
                            ID_AT_GID       = "0d000000"
                            ID_AT_EGID      = "0e000000"
                            ID_AT_SECURE    = "17000000"
                            AT_SECURE       = "00000000"
                            ID_AT_RANDOM    = "19000000"
                            ID_AT_HWCAP2    = "1a000000"
                            AT_HWCAP2       = "00000000"
                            ID_AT_EXECFN    = "1f000000"
                            AT_EXECFN       = "00000000"  # File name of executable
                            ID_AT_PLATFORM  = "f0000000"
                            ID_AT_NULL      = "00000000"
                            AT_NULL         = "00000000"

                        AT_HWCAP    = self.ql.addr_to_str(self.ql.elf_hwcap)  # mock cpuid 0x1f8bfbff
                        AT_PAGESZ   = self.ql.addr_to_str(self.ql.elf_pagesz)  # System page size, fixed in qiling
                        AT_PHDR     = self.ql.addr_to_str(self.ql.elf_phdr)  # Program headers for program
                        AT_PHENT    = self.ql.addr_to_str(self.ql.elf_phent)  # Size of program header entry
                        AT_PHNUM    = self.ql.addr_to_str(self.ql.elf_phnum)  # Number of program headers
                        AT_BASE     = self.ql.addr_to_str(self.ql.interp_base)  # Base address of interpreter
                        AT_FLAGS    = self.ql.addr_to_str(self.ql.elf_flags)
                        AT_ENTRY    = self.ql.addr_to_str(self.ql.elf_entry)  # Entry point of program
                        AT_UID      = self.ql.addr_to_str(self.ql.elf_guid)  # UID at 1000 fixed in qiling
                        AT_EUID     = self.ql.addr_to_str(self.ql.elf_guid)  # EUID at 1000 fixed in qiling
                        AT_GID      = self.ql.addr_to_str(self.ql.elf_guid)  # GID at 1000 fixed in qiling
                        AT_EGID     = self.ql.addr_to_str(self.ql.elf_guid)  # EGID at 1000 fixed in qiling
                        AT_RANDOM   = self.ql.addr_to_str(self.ql.randstraddr)  # Address of 16 random bytes
                        AT_PLATFORM = self.ql.addr_to_str(self.ql.cpustraddr)  # String identifying platform

                        auxvdata_c = (
                                        ANNEX + AT_SYSINFO_EHDR +
                                        ID_AT_HWCAP + AT_HWCAP +
                                        ID_AT_PAGESZ + AT_PAGESZ +
                                        ID_AT_CLKTCK + AT_CLKTCK +
                                        ID_AT_PHDR + AT_PHDR +
                                        ID_AT_PHENT + AT_PHENT +
                                        ID_AT_PHNUM + AT_PHNUM +
                                        ID_AT_BASE + AT_BASE +
                                        ID_AT_FLAGS + AT_FLAGS +
                                        ID_AT_ENTRY + AT_ENTRY +
                                        ID_AT_UID + AT_UID +
                                        ID_AT_EUID + AT_EUID +
                                        ID_AT_GID + AT_GID +
                                        ID_AT_EGID + AT_EGID +
                                        ID_AT_SECURE + AT_SECURE +
                                        ID_AT_RANDOM + AT_RANDOM +
                                        ID_AT_HWCAP2 + AT_HWCAP2 +
                                        ID_AT_EXECFN + AT_EXECFN +
                                        ID_AT_PLATFORM + AT_PLATFORM +
                                        ID_AT_NULL + AT_NULL
                                    )

                    auxvdata = self.bin_to_escstr(unhexlify(auxvdata_c))
                    self.send(b'l!' + auxvdata)

                elif subcmd.startswith('Xfer:exec-file:read:'):
                    self.send("l" + str(self.exe_abspath))

                elif subcmd.startswith('Xfer:libraries-svr4:read:'):
                    self.send("l<library-list-svr4 version=\"1.0\"/>")

                elif subcmd == "Attached":
                    self.send("")

                elif subcmd.startswith("C"):
                    self.send("")

                elif subcmd.startswith("L:"):
                    self.send("M001")

                elif subcmd == "fThreadInfo":
                    self.send("m0")

                elif subcmd == "sThreadInfo":
                    self.send("l")

                elif subcmd.startswith("TStatus"):
                    self.send("")

                elif subcmd == "Symbol":
                    self.send("OK")

                elif subcmd == "Offsets":
                    self.send("Text=0;Data=0;Bss=0")


            def handle_v(subcmd):

                if subcmd == 'MustReplyEmpty':
                    self.send("")

                elif subcmd.startswith('File:open'):
                    binname = subcmd.split(':')[-1].split(',')[0]
                    binname = unhexlify(binname).decode(encoding='UTF-8')
                    if binname != "just probing":
                        self.lib_abspath = str(os.path.join(self.rootfs_abspath,binname))
                        self.ql.dprint("gdb> opening file: %s" % (binname))
                        self.send("F5")
                    else:
                        self.send("F0")

                elif subcmd.startswith('File:pread:5'):

                    offset = subcmd.split(',')[-1]
                    count = subcmd.split(',')[-2]
                    offset = ((int(offset, base=16)))
                    count = ((int(count, base=16)))

                    if os.path.exists(self.lib_abspath):
                        with open(self.lib_abspath, "rb") as f:
                            preadheader = f.read()

                        if offset != 0:
                            shift_count = offset + count
                            read_offset = preadheader[offset:shift_count]
                        else:
                            read_offset = preadheader[offset:count]

                        preadheader_len = len(preadheader)

                        read_offset = self.bin_to_escstr(read_offset)

                        if count == 1 and (preadheader_len >= offset):
                            if read_offset:
                                self.send(b'F1;' + (read_offset))
                            else:
                                self.send('F1;\x00')

                        elif count > 1:
                            self.send(b'F' + (str(hex(count)[2:]).encode()) + b';' + (read_offset))

                        else:
                            self.send("F0;")

                    else:
                        self.send("F0;")

                elif subcmd.startswith('File:close'):
                    self.send("F0")

                elif subcmd.startswith('Kill'):
                    self.send('OK')
                    exit(1)

                elif subcmd.startswith('Cont'):
                    self.ql.dprint("gdb> Cont command received: %s" % subcmd)
                    if subcmd == 'Cont?':
                        if self.en_vcont == True:
                            self.send('vCont;c;C;s;S')
                        else:    
                            self.send('')
                    else:
                        subcmd = subcmd.split(';')
                        if subcmd[1] in ('c', 'C05'):
                            handle_c(subcmd)
                        elif subcmd[1] in ('s:1', 'S:1'):
                            handle_s(subcmd)
                else:
                    self.send("")


            def handle_s(subcmd):
                current_address = self.qldbg.current_address
                if current_address is None:
                    entry_point = self.qldbg.entry_point
                    if entry_point is not None:
                        self.qldbg.soft_bp = True
                        self.qldbg.resume_emu(entry_point)
                else:
                    self.qldbg.soft_bp = True
                    self.qldbg.resume_emu()
                self.send('S%.2x' % GDB_SIGNAL_TRAP)


            def handle_Z(subcmd):
                data = subcmd
                ztype = data[data.find('Z') + 1:data.find(',')]
                if ztype == '0':
                    ztype, address, value = data.split(',')
                    address = int(address, 16)
                    try:
                        self.qldbg.bp_insert(address)
                        self.send('OK')
                    except:
                        self.send('E22')
                else:
                    self.send('E22')


            def handle_z(subcmd):
                data = subcmd.split(',')
                if len(data) != 3:
                    self.send('E22')
                try:
                    type = data[0]
                    addr = int(data[1], 16)
                    length = data[2]
                    self.qldbg.bp_remove(type, addr, length)
                    self.send('OK')
                except:
                    self.send('E22')


            def handle_exclaim(subcmd):
                self.send('OK')

            commands = {
                '!': handle_exclaim,
                '?': handle_qmark,
                'c': handle_c,
                'C': handle_C,
                'D': handle_D,
                'g': handle_g,
                'G': handle_G,
                'H': handle_H,
                'm': handle_m,
                'M': handle_M,
                'p': handle_p,
                'P': handle_P,
                'q': handle_q,
                'Q': handle_Q,
                'v': handle_v,
                's': handle_s,
                'Z': handle_Z,
                'z': handle_z
            }

            cmd, subcmd = pkt[0], pkt[1:]
            if cmd == 'k':
                break

            if cmd not in commands:
                self.send('')
                self.ql.nprint("gdb> command not supported: %s" %(cmd))
                continue
            self.ql.dprint("gdb> received: %s%s" % (cmd,subcmd))
            commands[cmd](subcmd)

        self.close()


    def receive(self):
        '''Receive a packet from a GDB client'''
        csum = 0
        state = 'Finding SOP'
        packet = ''
        try:
            while True:
                c = self.netin.read(1)
                # self.ql.dprint(c)
                if c == '\x03':
                    return 'Error: CTRL+C'

                if len(c) != 1:
                    return 'Error: EOF'

                if state == 'Finding SOP':
                    if c == '$':
                        state = 'Finding EOP'
                elif state == 'Finding EOP':
                    if c == '#':
                        if csum != int(self.netin.read(2), 16):
                            raise Exception('invalid checksum')
                        self.last_pkt = packet
                        return 'Good'
                    else:
                        packet += c
                        csum = (csum + ord(c)) & 0xff
                else:
                    raise Exception('should not be here')
        except:
            self.close()
            raise


    def send(self, msg):
        """Send a packet to the GDB client"""
        if type(msg) == str:
            self.send_raw('$%s#%.2x' % (msg, checksum(msg)))
        else:
            self.clientsocket.send(b'$'+ msg + (b'#%.2x' % checksum(msg)))
            self.netout.flush()

        self.ql.dprint("gdb> send: $%s#%.2x" % (msg, checksum(msg)))

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()

