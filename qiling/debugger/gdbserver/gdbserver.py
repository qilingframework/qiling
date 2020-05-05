#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# gdbserver --remote-debug --disable-packet=threads,vCont 0.0.0.0:9999 /path/to binary
# documentation: according to https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol

import struct, os, re, socket
from binascii import unhexlify

from qiling.debugger.gdbserver import qldbg
from qiling.const import *
from qiling.utils import *

GDB_SIGNAL_INT  = 2
GDB_SIGNAL_SEGV = 11
GDB_SIGNAL_GILL = 4
GDB_SIGNAL_STOP = 17
GDB_SIGNAL_TRAP = 5
GDB_SIGNAL_BUS  = 10

def checksum(data):
    checksum = 0
    for c in data:
        if type(c) == str:
            checksum += (ord(c))
        else:
            checksum += c
    return checksum & 0xff


class GDBSERVERsession(object):
    """docstring for Debugsession"""
    def __init__(self, ql, clientsocket, exit_point, mappings):
        super(GDBSERVERsession, self).__init__()
        self.ql             = ql
        self.clientsocket   = clientsocket
        self.netin          = clientsocket.makefile('r')
        self.netout         = clientsocket.makefile('w')
        self.last_pkt       = None
        self.en_vcont       = False
        self.gdb            = qldbg.Qldbg()
        self.gdb.initialize(self.ql, exit_point=exit_point, mappings=mappings)
        self.exe_abspath    = (os.path.abspath(self.ql.filename[0]))
        self.rootfs_abspath = (os.path.abspath(self.ql.rootfs)) 
        
        if self.ql.ostype in (QL_OS.LINUX, QL_OS.FREEBSD) and not self.ql.shellcoder:
            self.entry_point = self.ql.os.elf_entry
        else:
            self.entry_point = self.ql.os.entry_point

        self.gdb.bp_insert(self.entry_point)


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
                a = str("7d%s" % a)
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
                def gdbqmark_converter(arch):
                    """
                    MIPS32_EL : gdbserver response ("$T051d:00e7ff7f;25:40ccfc77;#65")
                    MIPS32_EB : gdbserver response ("$T051d:7fff6dc0;25:77fc4880;thread:28fa;core:0;");
                    ARM64: gdbserver response "$T051d:0*,;1f:80f6f*"ff0* ;20:c02cfdb7f* 0* ;thread:p1f9.1f9;core:0;#56");
                    ARM: gdbserver $T050b:0*"00;0d:e0f6ffbe;0f:8079fdb6;#ae"
                    """
                    adapter = {
                        QL_ARCH.X86          : [ 0x05, 0x04, 0x08 ],
                        QL_ARCH.X8664        : [ 0x06, 0x07, 0x10 ],
                        QL_ARCH.MIPS       : [ 0x1d, 0x00, 0x25 ],        
                        QL_ARCH.ARM          : [ 0x0b, 0x0d, 0x0f ],
                        QL_ARCH.ARM64        : [ 0x1d, 0xf1, 0x20 ]
                        }
                    return adapter.get(arch)

                idhex, spid, pcid  = gdbqmark_converter(self.ql.archtype)  
                sp          = self.ql.arch.addr_to_str(self.ql.reg.arch_sp)
                pc          = self.ql.arch.addr_to_str(self.ql.reg.arch_pc)
                nullfill    = "0" * int(self.ql.archbit / 4)

                if self.ql.archtype== QL_ARCH.MIPS:
                    if self.ql.archendian == QL_ENDIAN.EB:
                        sp = self.ql.arch.addr_to_str(self.ql.reg.arch_sp, endian ="little")
                        pc = self.ql.arch.addr_to_str(self.ql.reg.arch_pc, endian ="little")
                    self.send('T%.2x%.2x:%s;%.2x:%s;' %(GDB_SIGNAL_TRAP, idhex, sp, pcid, pc))
                else:    
                    self.send('T%.2x%.2x:%s;%.2x:%s;%.2x:%s;' %(GDB_SIGNAL_TRAP, idhex, nullfill, spid, sp, pcid, pc))


            def handle_c(subcmd):
                self.gdb.resume_emu(self.ql.reg.arch_pc)
                
                if self.gdb.bp_list is ([self.entry_point]):
                    self.send("W00")
                else:
                    self.send(('S%.2x' % GDB_SIGNAL_TRAP))


            handle_C = handle_c


            def handle_g(subcmd):
                s = ''
                if self.ql.archtype== QL_ARCH.X86:
                    for reg in self.ql.reg.table[:16]:
                        r = self.ql.reg.read(reg)
                        tmp = self.ql.arch.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype== QL_ARCH.X8664:
                    for reg in self.ql.reg.table[:24]:
                        r = self.ql.reg.read(reg)
                        if self.ql.reg.bit(reg) == 64:
                            tmp = self.ql.arch.addr_to_str(r)
                        elif self.ql.reg.bit(reg) == 32:
                            tmp = self.ql.arch.addr_to_str(r, short = True)
                        s += tmp
                
                elif self.ql.archtype== QL_ARCH.ARM:
                    for reg in self.ql.reg.table[:17]:
                        r = self.ql.reg.read(reg)
                        tmp = self.ql.arch.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype== QL_ARCH.ARM64:
                    for reg in self.ql.reg.table[:33]:
                        r = self.ql.reg.read(reg)
                        tmp = self.ql.arch.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype== QL_ARCH.MIPS:
                    for reg in self.ql.reg.table[:38]:
                        r = self.ql.reg.read(reg)
                        if self.ql.archendian == QL_ENDIAN.EB:
                            tmp = self.ql.arch.addr_to_str(r, endian ="little")
                        else:
                            tmp = self.ql.arch.addr_to_str(r)    
                        s += tmp

                self.send(s)


            def handle_G(subcmd):
                count = 0
                if self.ql.archtype== QL_ARCH.X86:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.ql.reg.table[count], reg_data)
                        count += 1

                elif self.ql.archtype== QL_ARCH.X8664:
                    for i in range(0, 17*16, 16):
                        reg_data = subcmd[i:i+15]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.ql.reg.table[count], reg_data)
                        count += 1
                    for j in range(17*16, 17*16+15*8, 8):
                        reg_data = subcmd[j:j+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.ql.reg.table[count], reg_data)
                        count += 1
                
                elif self.ql.archtype== QL_ARCH.ARM:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i + 7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.ql.reg.table[count], reg_data)
                        count += 1

                elif self.ql.archtype== QL_ARCH.ARM64:
                    for i in range(0, len(subcmd), 16):
                        reg_data = subcmd[i:i+15]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.ql.reg.table[count], reg_data)
                        count += 1

                elif self.ql.archtype== QL_ARCH.MIPS:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.ql.reg.table[count], reg_data)
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
                        mem = self.ql.mem.read(addr + s, 1)
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
                    self.ql.mem.write(addr, data)
                    self.send('OK')
                except:
                    self.send('E01')


            def handle_p(subcmd):
                reg_index = int(subcmd, 16)
                reg_value = None
                try:
                    if self.ql.archtype== QL_ARCH.X86:
                        if reg_index <= 24:
                            reg_value = self.ql.reg.read(self.ql.reg.table[reg_index-1])
                        else:
                            reg_value = 0
                        reg_value = self.ql.arch.addr_to_str(reg_value)
                    
                    elif self.ql.archtype== QL_ARCH.X8664:
                        if reg_index <= 32:
                            reg_value = self.ql.reg.read(self.ql.reg.table[reg_index-1])
                        else:
                            reg_value = 0
                        if reg_index <= 17:
                            reg_value = self.ql.arch.addr_to_str(reg_value)
                        elif 17 < reg_index:
                            reg_value = self.ql.arch.addr_to_str(reg_value, short = True)
                    
                    elif self.ql.archtype== QL_ARCH.ARM:
                        if reg_index < 17:
                            reg_value = self.ql.reg.read(self.ql.reg.table[reg_index - 1])
                        else:
                            reg_value = 0
                        reg_value = self.ql.arch.addr_to_str(reg_value)

                    elif self.ql.archtype== QL_ARCH.ARM64:
                        if reg_index <= 32:
                            reg_value = self.ql.reg.read(self.ql.reg.table[reg_index - 1])
                        else:
                            reg_value = 0
                            reg_value = self.ql.arch.addr_to_str(reg_value)

                    elif self.ql.archtype== QL_ARCH.MIPS:
                        if reg_index <= 37:
                            reg_value = self.ql.reg.read(self.ql.reg.table[reg_index - 1])
                        else:
                            reg_value = 0
                        if self.ql.archendian == QL_ENDIAN.EL:
                            reg_value = self.ql.arch.addr_to_str(reg_value, endian="little")
                        else:
                            reg_value = self.ql.arch.addr_to_str(reg_value)
                    
                    if type(reg_value) is not str:
                        reg_value = self.ql.arch.addr_to_str(reg_value)

                    self.send(reg_value)
                except:
                    self.close()
                    raise


            def handle_P(subcmd):
                reg_index, reg_data = subcmd.split('=')
                reg_index = int(reg_index, 16)
                if self.ql.archtype== QL_ARCH.X86:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(self.ql.reg.table[reg_index], reg_data)
                
                elif self.ql.archtype== QL_ARCH.X8664:
                    if reg_index <= 17:
                        reg_data = int(reg_data, 16)
                        reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                        sself.ql.reg.write(self.ql.reg.table[reg_index], reg_data)
                    else:
                        reg_data = int(reg_data[:8], 16)
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                        self.ql.reg.write(self.ql.reg.table[reg_index], reg_data)
                
                elif self.ql.archtype== QL_ARCH.ARM:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(self.ql.reg.table[reg_index], reg_data)

                elif self.ql.archtype== QL_ARCH.ARM64:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                    self.ql.reg.write(self.ql.reg.table[reg_index], reg_data)

                elif self.ql.archtype== QL_ARCH.MIPS:
                    reg_data = int(reg_data, 16)
                    if self.ql.archendian == QL_ENDIAN.EL:
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='little')
                    else:
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(self.ql.reg.table[reg_index], reg_data)

                self.ql.nprint("gdb> Write to register %x with %x\n" % (self.ql.reg.table[reg_index], reg_data))
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
                    # might or might not need for multi thread
                    if self.ql.multithread == False:
                        self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")
                    else:    
                        self.send("PacketSize=47ff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;FastTracepoints+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;Qbtrace:bts+;Qbtrace-conf:bts:size+;Qbtrace:pt+;Qbtrace-conf:pt:size+;Qbtrace:off+;qXfer:btrace:read+;qXfer:btrace-conf:read+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")
                elif subcmd.startswith('Xfer:features:read'):
                    xfercmd_file    = subcmd.split(':')[3]
                    xfercmd_abspath = os.path.dirname(os.path.abspath(__file__))
                    xml_folder      = arch_convert_str(self.ql.archtype)
                    xfercmd_file    = os.path.join(xfercmd_abspath,"xml",xml_folder, xfercmd_file)                        

                    if os.path.exists(xfercmd_file) and self.ql.ostype is not QL_OS.WINDOWS:
                        f = open(xfercmd_file, 'r')
                        file_contents = f.read()
                        self.send("l%s" % file_contents)
                    else:
                        self.ql.nprint("gdb> Xml file not found: %s\n" % (xfercmd_file))


                elif subcmd.startswith('Xfer:threads:read::0,'):
                    file_contents = ("<threads>\r\n<thread id=\"2048\" core=\"3\" name=\"" + self.ql.targetname + "\"/>\r\n</threads>")
                    self.send("l" + file_contents)

                elif subcmd.startswith('Xfer:auxv:read::'):
                    if self.ql.shellcoder:
                        return
                    if self.ql.ostype in (QL_OS.LINUX, QL_OS.FREEBSD) :
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

                        AT_HWCAP    = self.ql.arch.addr_to_str(self.ql.loader.elf_hwcap)  # mock cpuid 0x1f8bfbff
                        AT_PAGESZ   = self.ql.arch.addr_to_str(self.ql.loader.elf_pagesz)  # System page size, fixed in qiling
                        AT_PHDR     = self.ql.arch.addr_to_str(self.ql.loader.elf_phdr)  # Program headers for program
                        AT_PHENT    = self.ql.arch.addr_to_str(self.ql.loader.elf_phent)  # Size of program header entry
                        AT_PHNUM    = self.ql.arch.addr_to_str(self.ql.loader.elf_phnum)  # Number of program headers
                        AT_BASE     = self.ql.arch.addr_to_str(self.ql.loader.interp_address)  # Base address of interpreter
                        AT_FLAGS    = self.ql.arch.addr_to_str(self.ql.loader.elf_flags)
                        AT_ENTRY    = self.ql.arch.addr_to_str(self.ql.loader.elf_entry)  # Entry point of program
                        AT_UID      = self.ql.arch.addr_to_str(self.ql.loader.elf_guid)  # UID at 1000 fixed in qiling
                        AT_EUID     = self.ql.arch.addr_to_str(self.ql.loader.elf_guid)  # EUID at 1000 fixed in qiling
                        AT_GID      = self.ql.arch.addr_to_str(self.ql.loader.elf_guid)  # GID at 1000 fixed in qiling
                        AT_EGID     = self.ql.arch.addr_to_str(self.ql.loader.elf_guid)  # EGID at 1000 fixed in qiling
                        AT_RANDOM   = self.ql.arch.addr_to_str(self.ql.loader.randstraddr)  # Address of 16 random bytes
                        AT_PLATFORM = self.ql.arch.addr_to_str(self.ql.loader.cpustraddr)  # String identifying platform

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
                        #self.send(b'l!%s' % auxvdata)
                    else:
                        auxvdata = b""
                    
                    self.send(b'l!%s' % auxvdata)

                elif subcmd.startswith('Xfer:exec-file:read:'):
                    self.send("l%s" % str(self.exe_abspath))


                elif subcmd.startswith('Xfer:libraries-svr4:read:'):
                    if self.ql.ostype in (QL_OS.LINUX, QL_OS.FREEBSD):
                        xml_addr_mapping=("<library-list-svr4 version=\"1.0\">")
                        """
                        FIXME: need to find out when do we need this
                        """
                        #for s, e, info in self.ql.map_info:
                        #    addr_mapping += ("<library name=\"%s\" lm=\"0x%x\" l_addr=\"%x\" l_ld=\"\"/>" %(info, e, s)) 
                        xml_addr_mapping += ("</library-list-svr4>")
                        self.send("l%s" % xml_addr_mapping)
                    else:     
                        self.send("l<library-list-svr4 version=\"1.0\"></library-list-svr4>")


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

                elif subcmd == ("TStatus"):
                    self.send("T0;tnotrun:0;tframes:0;tcreated:0;tfree:50*!;tsize:50*!;circular:0;disconn:0;starttime:0;stoptime:0;username:;notes::")

                elif subcmd == ("TfV"):
                    self.send("l")

                elif subcmd == ("TsV"):
                    self.send("l")

                elif subcmd == ("TfP"):
                    self.send("l")

                elif subcmd == ("TsP"):
                    self.send("l")


                elif subcmd.startswith("Symbol"):
                    self.send("")

                elif subcmd.startswith("Attached"):
                    self.send("")

                elif subcmd == "Offsets":
                    self.send("Text=0;Data=0;Bss=0")


            def handle_v(subcmd):

                if subcmd == 'MustReplyEmpty':
                    self.send("")

                elif subcmd.startswith('File:open'):
                    self.lib_path = subcmd.split(':')[-1].split(',')[0]
                    self.lib_path = unhexlify(self.lib_path).decode(encoding='UTF-8')
                    
                    if self.lib_path != "just probing":
                        if self.lib_path.startswith(self.rootfs_abspath):
                            self.lib_abspath = self.lib_path
                        else:
                            self.lib_abspath = self.ql.os.transform_to_real_path(self.lib_path)

                        self.ql.dprint(D_INFO, "gdb> target file: %s" % (self.lib_abspath))

                        if os.path.exists(self.lib_abspath):
                            self.send("F5")
                        else:
                            self.send("F0")   
                    else:
                        self.send("F0")

                elif subcmd.startswith('File:pread:'):

                    offset = subcmd.split(',')[-1]
                    count = subcmd.split(',')[-2]
                    offset = ((int(offset, base=16)))
                    count = ((int(count, base=16)))

                    if os.path.exists(self.lib_abspath) and not (self.lib_path).startswith("/proc"):

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
                    
                    elif re.match("\/proc\/.*\/maps", self.lib_abspath):
                        self.send("F0;")    
                    
                    else:
                        self.send("F0;")

                elif subcmd.startswith('File:close'):
                    self.send("F0")

                elif subcmd.startswith('Kill'):
                    self.send('OK')
                    exit(1)

                elif subcmd.startswith('Cont'):
                    self.ql.dprint(D_INFO, "gdb> Cont command received: %s" % subcmd)
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
                current_address = self.gdb.current_address
                if current_address is None:
                    entry_point = self.gdb.entry_point
                    if entry_point is not None:
                        self.gdb.soft_bp = True
                        self.gdb.resume_emu(entry_point)
                else:
                    self.gdb.soft_bp = True
                    self.gdb.resume_emu()
                self.send('S%.2x' % GDB_SIGNAL_TRAP)


            def handle_Z(subcmd):
                data = subcmd
                ztype = data[data.find('Z') + 1:data.find(',')]
                if ztype == '0':
                    ztype, address, value = data.split(',')
                    address = int(address, 16)
                    try:
                        self.gdb.bp_insert(address)
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
                    self.gdb.bp_remove(type, addr, length)
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
                's': handle_s,
                'v': handle_v,
                'Z': handle_Z,
                'z': handle_z
            }

            cmd, subcmd = pkt[0], pkt[1:]
            if cmd == 'k':
                break

            if cmd not in commands:
                self.send('')
                self.ql.nprint("gdb> Command not supported: %s\n" %(cmd))
                continue
            self.ql.dprint(D_INFO, "gdb> received: %s%s" % (cmd, subcmd))
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
            self.clientsocket.send(b'$%s#%.2x' % (msg, checksum(msg)))
            self.netout.flush()

        self.ql.dprint(D_INFO, "gdb> send: $%s#%.2x" % (msg, checksum(msg)))

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()