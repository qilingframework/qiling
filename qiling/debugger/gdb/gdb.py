#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# gdbserver --remote-debug 0.0.0.0:9999 /path/to binary
# documentation: according to https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol

import struct, os, socket
from binascii import unhexlify
from typing import Iterator, Literal

from qiling import Qiling
from qiling.const import *
from qiling.utils import *
from qiling.debugger import QlDebugger
from qiling.arch.x86_const import reg_map_16 as x86_reg_map_16
from qiling.arch.x86_const import reg_map_32 as x86_reg_map_32
from qiling.arch.x86_const import reg_map_64 as x86_reg_map_64
from qiling.arch.x86_const import reg_map_misc as x86_reg_map_misc
from qiling.arch.x86_const import reg_map_st as x86_reg_map_st
from qiling.arch.arm_const import reg_map as arm_reg_map
from qiling.arch.arm64_const import reg_map as arm64_reg_map
from qiling.arch.mips_const import reg_map as mips_reg_map
from qiling.loader.elf import AUX

from .utils import QlGdbUtils

GDB_SIGNAL_INT  = 2
GDB_SIGNAL_SEGV = 11
GDB_SIGNAL_GILL = 4
GDB_SIGNAL_STOP = 17
GDB_SIGNAL_TRAP = 5
GDB_SIGNAL_BUS  = 10


class QlGdb(QlDebugger, object):
    """docstring for Debugsession"""
    def __init__(self, ql: Qiling, ip: str = '127.0.01', port: int = 9999):
        super(QlGdb, self).__init__(ql)

        self.ql             = ql
        self.last_pkt       = None
        self.exe_abspath    = os.path.abspath(self.ql.argv[0])
        self.rootfs_abspath = os.path.abspath(self.ql.rootfs)
        self.gdb            = QlGdbUtils()

        if type(port) is str:
            port = int(port, 0)

        self.ip = ip
        self.port = port

        if self.ql.baremetal:
            load_address = self.ql.loader.load_address
            exit_point = load_address + os.path.getsize(ql.path)
        elif self.ql.code:
            load_address = self.ql.os.entry_point
            exit_point = load_address + len(ql.code)
        else:
            load_address = ql.loader.load_address
            exit_point = load_address + os.path.getsize(ql.path)

        if self.ql.baremetal:
            self.entry_point = self.ql.loader.entry_point
        elif self.ql.ostype in (QL_OS.LINUX, QL_OS.FREEBSD) and not self.ql.code:
            self.entry_point = self.ql.os.elf_entry
        else:
            self.entry_point = self.ql.os.entry_point

        # Only part of the binary file will be debugged.
        if self.ql.entry_point is not None and self.ql.exit_point is not None:
            self.entry_point = self.ql.entry_point
            exit_point = self.ql.exit_point

        self.gdb.initialize(self.ql, self.entry_point, exit_point=exit_point, mappings=[(hex(load_address))])

        #Setup register tables, order of tables is important
        self.tables = {
            QL_ARCH.A8086       : list({**x86_reg_map_16, **x86_reg_map_misc}.keys()),
            QL_ARCH.X86         : list({**x86_reg_map_32, **x86_reg_map_misc, **x86_reg_map_st}.keys()),
            QL_ARCH.X8664       : list({**x86_reg_map_64, **x86_reg_map_misc, **x86_reg_map_st}.keys()),
            QL_ARCH.ARM         : list({**arm_reg_map}.keys()),
            QL_ARCH.CORTEX_M    : list({**arm_reg_map}.keys()),
            QL_ARCH.ARM64       : list({**arm64_reg_map}.keys()),
            QL_ARCH.MIPS        : list({**mips_reg_map}.keys()),
        }

    def addr_to_str(self, addr: int, short: bool = False, endian: Literal['little', 'big'] = 'big') -> str:
        # a hacky way to divide archbits by 2 if short, and leave it unchanged if not
        nbits = self.ql.archbit // (int(short) + 1)

        if nbits == 64:
            s = f'{int.from_bytes(self.ql.pack64(addr), byteorder=endian):016x}'

        elif nbits == 32:
            s = f'{int.from_bytes(self.ql.pack32(addr), byteorder=endian):08x}'

        elif nbits == 16:
            s = f'{int.from_bytes(self.ql.pack16(addr), byteorder=endian):04x}'

        else:
            raise RuntimeError

        return s

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

            if a in (42,35,36, 125):
                a = a ^ 0x20
                a = (str(hex(a)[2:]))
                a = incomplete_hex_check(a)
                a = str("7d%s" % a)
            else:
                a = (str(hex(a)[2:]))
                a = incomplete_hex_check(a)

            rawbin_escape += a

        return unhexlify(rawbin_escape)

    def setup_server(self):
        self.ql.log.info("gdb> Listening on %s:%u" % (self.ip, self.port))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(1)
        clientsocket, addr = sock.accept()

        self.sock           = sock
        self.clientsocket   = clientsocket
        self.netin          = clientsocket.makefile('r')
        self.netout         = clientsocket.makefile('w')

    def close(self):
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()
        self.sock.close()

    def run(self):
        self.setup_server()

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
                        QL_ARCH.A8086        : [ 0x05, 0x04, 0x08 ],
                        QL_ARCH.X86          : [ 0x05, 0x04, 0x08 ],
                        QL_ARCH.X8664        : [ 0x06, 0x07, 0x10 ],
                        QL_ARCH.MIPS         : [ 0x1d, 0x00, 0x25 ],        
                        QL_ARCH.ARM          : [ 0x0b, 0x0d, 0x0f ],
                        QL_ARCH.CORTEX_M     : [ 0x0b, 0x0d, 0x0f ],
                        QL_ARCH.ARM64        : [ 0x1d, 0xf1, 0x20 ]
                        }
                    return adapter.get(arch)

                idhex, spid, pcid  = gdbqmark_converter(self.ql.archtype)  
                sp          = self.addr_to_str(self.ql.reg.arch_sp)
                pc          = self.addr_to_str(self.ql.reg.arch_pc)
                nullfill    = "0" * int(self.ql.archbit / 4)

                if self.ql.archtype== QL_ARCH.MIPS:
                    if self.ql.archendian == QL_ENDIAN.EB:
                        sp = self.addr_to_str(self.ql.reg.arch_sp, endian ="little")
                        pc = self.addr_to_str(self.ql.reg.arch_pc, endian ="little")
                    self.send('T%.2x%.2x:%s;%.2x:%s;' %(GDB_SIGNAL_TRAP, idhex, sp, pcid, pc))
                else:    
                    self.send('T%.2x%.2x:%s;%.2x:%s;%.2x:%s;' %(GDB_SIGNAL_TRAP, idhex, nullfill, spid, sp, pcid, pc))


            def handle_c(subcmd):
                self.gdb.resume_emu(self.ql.reg.arch_pc)

                if self.gdb.bp_list == [self.entry_point]:
                    self.send("W00")
                else:
                    self.send(('S%.2x' % GDB_SIGNAL_TRAP))


            handle_C = handle_c


            def handle_g(subcmd):
                s = ''

                if self.ql.archtype== QL_ARCH.A8086:
                    for reg in self.tables[QL_ARCH.A8086][:16]:
                        r = self.ql.reg.read(reg)
                        tmp = self.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype== QL_ARCH.X86:
                    for reg in self.tables[QL_ARCH.X86][:16]:
                        r = self.ql.reg.read(reg)
                        tmp = self.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype== QL_ARCH.X8664:
                    for reg in self.tables[QL_ARCH.X8664][:24]:
                        r = self.ql.reg.read(reg)
                        if self.ql.reg.bit(reg) == 64:
                            tmp = self.addr_to_str(r)
                        elif self.ql.reg.bit(reg) == 32:
                            tmp = self.addr_to_str(r, short = True)
                        s += tmp
                
                elif self.ql.archtype == QL_ARCH.ARM:
                    

                    # r0-r12,sp,lr,pc,cpsr ,see https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=gdb/arch/arm.h;h=fa589fd0582c0add627a068e6f4947a909c45e86;hb=HEAD#l127
                    for reg in self.tables[QL_ARCH.ARM][:16] + [self.tables[QL_ARCH.ARM][25]]:
                        # if reg is pc, make sure to take thumb mode into account
                        r = self.ql.arch.get_pc() if reg == "pc" else self.ql.reg.read(reg)

                        tmp = self.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype == QL_ARCH.ARM64:
                    for reg in self.tables[QL_ARCH.ARM64][:33]:
                        r = self.ql.reg.read(reg)
                        tmp = self.addr_to_str(r)
                        s += tmp

                elif self.ql.archtype == QL_ARCH.MIPS:
                    for reg in self.tables[QL_ARCH.MIPS][:38]:
                        r = self.ql.reg.read(reg)
                        if self.ql.archendian == QL_ENDIAN.EL:
                            tmp = self.addr_to_str(r, endian ="little")
                        else:
                            tmp = self.addr_to_str(r)    
                        s += tmp

                self.send(s)


            def handle_G(subcmd):
                count = 0

                if self.ql.archtype == QL_ARCH.A8086:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.A8086][count], reg_data)
                        count += 1

                elif self.ql.archtype == QL_ARCH.X86:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.X86][count], reg_data)
                        count += 1
                

                elif self.ql.archtype == QL_ARCH.X8664:
                    for i in range(0, 17*16, 16):
                        reg_data = subcmd[i:i+15]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.X8664][count], reg_data)
                        count += 1
                    for j in range(17*16, 17*16+15*8, 8):
                        reg_data = subcmd[j:j+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.X8664][count], reg_data)
                        count += 1
                
                elif self.ql.archtype == QL_ARCH.ARM:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i + 7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.ARM][count], reg_data)
                        count += 1

                elif self.ql.archtype == QL_ARCH.ARM64:
                    for i in range(0, len(subcmd), 16):
                        reg_data = subcmd[i:i+15]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.ARM64][count], reg_data)
                        count += 1

                elif self.ql.archtype == QL_ARCH.MIPS:
                    for i in range(0, len(subcmd), 8):
                        reg_data = subcmd[i:i+7]
                        reg_data = int(reg_data, 16)
                        self.ql.reg.write(self.tables[QL_ARCH.MIPS][count], reg_data)
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
                data = bytes.fromhex(data)
                try:
                    self.ql.mem.write(addr, data)
                    self.send('OK')
                except:
                    self.send('E01')


            def handle_p(subcmd):
                reg_index = int(subcmd, 16)
                reg_value = None
                try:
                    if self.ql.archtype== QL_ARCH.A8086:
                        if reg_index <= 9:
                            reg_value = self.ql.reg.read(self.tables[QL_ARCH.A8086][reg_index-1])
                        else:
                            reg_value = 0
                        reg_value = self.addr_to_str(reg_value)

                    elif self.ql.archtype== QL_ARCH.X86:
                        if reg_index <= 24:
                            reg_value = self.ql.reg.read(self.tables[QL_ARCH.X86][reg_index-1])
                        else:
                            reg_value = 0
                        reg_value = self.addr_to_str(reg_value)
                    
                    elif self.ql.archtype== QL_ARCH.X8664:
                        if reg_index <= 32:
                            reg_value = self.ql.reg.read(self.tables[QL_ARCH.X8664][reg_index-1])
                        else:
                            reg_value = 0
                        if reg_index <= 17:
                            reg_value = self.addr_to_str(reg_value)
                        elif 17 < reg_index:
                            reg_value = self.addr_to_str(reg_value, short = True)
                    
                    elif self.ql.archtype== QL_ARCH.ARM:
                        if reg_index < 26:
                            reg_value = self.ql.reg.read(self.tables[QL_ARCH.ARM][reg_index - 1])
                        else:
                            reg_value = 0
                        reg_value = self.addr_to_str(reg_value)

                    elif self.ql.archtype== QL_ARCH.ARM64:
                        if reg_index <= 32:
                            reg_value = self.ql.reg.read(self.tables[QL_ARCH.ARM64][reg_index - 1])
                        else:
                            reg_value = 0
                            reg_value = self.addr_to_str(reg_value)

                    elif self.ql.archtype== QL_ARCH.MIPS:
                        if reg_index <= 37:
                            reg_value = self.ql.reg.read(self.tables[QL_ARCH.MIPS][reg_index - 1])
                        else:
                            reg_value = 0
                        if self.ql.archendian == QL_ENDIAN.EL:
                            reg_value = self.addr_to_str(reg_value, endian="little")
                        else:
                            reg_value = self.addr_to_str(reg_value)
                    
                    if type(reg_value) is not str:
                        reg_value = self.addr_to_str(reg_value)

                    self.send(reg_value)
                except:
                    self.close()
                    raise


            def handle_P(subcmd):
                reg_index, reg_data = subcmd.split('=')
                reg_index = int(reg_index, 16)
                reg_name = self.tables[self.ql.archtype][reg_index]
                
                if self.ql.archtype== QL_ARCH.A8086:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(reg_name, reg_data)

                elif self.ql.archtype== QL_ARCH.X86:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(reg_name, reg_data)
                
                elif self.ql.archtype== QL_ARCH.X8664:
                    if reg_index <= 17:
                        reg_data = int(reg_data, 16)
                        reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                        self.ql.reg.write(reg_name, reg_data)
                    else:
                        reg_data = int(reg_data[:8], 16)
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                        self.ql.reg.write(reg_name, reg_data)
                
                elif self.ql.archtype== QL_ARCH.ARM:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(reg_name, reg_data)

                elif self.ql.archtype== QL_ARCH.ARM64:
                    reg_data = int(reg_data, 16)
                    reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                    self.ql.reg.write(reg_name, reg_data)

                elif self.ql.archtype== QL_ARCH.MIPS:
                    reg_data = int(reg_data, 16)
                    if self.ql.archendian == QL_ENDIAN.EL:
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='little')
                    else:
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.reg.write(reg_name, reg_data)

                if reg_name == self.ql.reg.arch_pc_name:
                    self.gdb.current_address = reg_data

                self.ql.log.info("gdb> Write to register %s with %x\n" % (self.tables[self.ql.archtype][reg_index], reg_data))
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

                elif subcmd.startswith('qemu'):
                    self.send('')

            def handle_D(subcmd):
                self.send('OK')

            def handle_q(subcmd):
                if subcmd.startswith('Supported:'):
                    # might or might not need for multi thread
                    if self.ql.multithread == False:
                        self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;no-resumed+")
                    else:    
                        self.send("PacketSize=47ff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;FastTracepoints+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;Qbtrace:bts+;Qbtrace-conf:bts:size+;Qbtrace:pt+;Qbtrace-conf:pt:size+;Qbtrace:off+;qXfer:btrace:read+;qXfer:btrace-conf:read+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")
                elif subcmd.startswith('Xfer:features:read'):
                    xfercmd_file    = subcmd.split(':')[3]
                    xfercmd_abspath = os.path.dirname(os.path.abspath(__file__))
                    xml_folder      = arch_convert_str(self.ql.archtype).lower()
                    xfercmd_file    = os.path.join(xfercmd_abspath,"xml",xml_folder, xfercmd_file)                        

                    if os.path.exists(xfercmd_file) and self.ql.ostype is not QL_OS.WINDOWS:
                        with open(xfercmd_file, 'r') as f:
                            file_contents = f.read()
                            self.send("l%s" % file_contents)
                    else:
                        self.ql.log.info("gdb> Platform is not supported by xml or xml file not found: %s\n" % (xfercmd_file))
                        self.send("l")


                elif subcmd.startswith('Xfer:threads:read::0,'):
                    if self.ql.ostype in QL_OS_NONPID or self.ql.baremetal:
                        self.send("l")
                    else:    
                        file_contents = ("<threads>\r\n<thread id=\""+ str(self.ql.os.pid) + "\" core=\"1\" name=\"" + self.ql.targetname + "\"/>\r\n</threads>")
                        self.send("l" + file_contents)

                elif subcmd.startswith('Xfer:auxv:read::'):
                    if self.ql.code:
                        return

                    if self.ql.ostype in (QL_OS.LINUX, QL_OS.FREEBSD):
                        def __read_auxv() -> Iterator[int]:
                            auxv_entries = (
                                AUX.AT_HWCAP,
                                AUX.AT_PAGESZ,
                                AUX.AT_CLKTCK,
                                AUX.AT_PHDR,
                                AUX.AT_PHENT,
                                AUX.AT_PHNUM,
                                AUX.AT_BASE,
                                AUX.AT_FLAGS,
                                AUX.AT_ENTRY,
                                AUX.AT_UID,
                                AUX.AT_EUID,
                                AUX.AT_GID,
                                AUX.AT_EGID,
                                AUX.AT_SECURE,
                                AUX.AT_RANDOM,
                                AUX.AT_HWCAP2,
                                AUX.AT_EXECFN,
                                AUX.AT_PLATFORM,
                                AUX.AT_NULL
                            )

                            for e in auxv_entries:
                                yield e.value
                                yield self.ql.loader.aux_vec[e]

                        annex = self.addr_to_str(0)[:-2]
                        sysinfo_ehdr = self.addr_to_str(0)

                        auxvdata_c = unhexlify(''.join([annex, sysinfo_ehdr] + [self.addr_to_str(val) for val in __read_auxv()]))
                        auxvdata = self.bin_to_escstr(auxvdata_c)
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

                elif subcmd.startswith("Xfer:btrace-conf:read:"):
                     self.send("E.Btrace not enabled.")

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
                    if self.ql.ostype == QL_OS.UEFI or self.ql.baremetal:
                        self.send("F-1")
                        return

                    (file_path, flags, mode) = subcmd.split(':')[-1].split(',')
                    file_path = unhexlify(file_path).decode(encoding='UTF-8')
                    flags = int(flags, base=16)
                    mode = int(mode, base=16)
                    if file_path.startswith(self.rootfs_abspath):
                        file_abspath = file_path
                    else:
                        file_abspath = self.ql.os.path.transform_to_real_path(file_path)
                    
                    self.ql.log.debug("gdb> target file: %s" % (file_abspath))
                    if os.path.exists(file_abspath) and not (file_path).startswith("/proc"):
                        fd = os.open(file_abspath, flags, mode)
                        self.send("F%x" % fd)
                    else:
                        self.send("F-1")
                        return                        

                elif subcmd.startswith('File:pread:'):
                    (fd, count, offset) = subcmd.split(':')[-1].split(',')

                    fd = int(fd, base=16)
                    offset = int(offset, base=16)
                    count = int(count, base=16)

                    data = os.pread(fd, count, offset)
                    size = len(data)
                    data = self.bin_to_escstr(data)

                    if data:
                        self.send(("F%x;" % size).encode() + (data))
                    else:
                        self.send("F0;")

                elif subcmd.startswith('File:close'):
                    fd = subcmd.split(':')[-1]
                    fd = int(fd, base=16)
                    os.close(fd)
                    self.send("F0")

                elif subcmd.startswith('Kill'):
                    self.send('OK')

                elif subcmd.startswith('Cont'):
                    self.ql.log.debug("gdb> Cont command received: %s" % subcmd)
                    if subcmd == 'Cont?':
                        self.send('vCont;c;C;t;s;S;r')
                    elif subcmd.startswith ("Cont;"):
                        subcmd = subcmd.split(';')
                        subcmd = subcmd[1].split(':')
                        if subcmd[0] in ('c', 'C05'):
                            handle_c(subcmd)
                        elif subcmd[0] in ('S', 's', 'S05'):
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


            def handle_X(subcmd):
                self.send('')


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
                    self.gdb.bp_remove(addr, type, length)
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
                'X': handle_X,
                'Z': handle_Z,
                'z': handle_z
            }

            cmd, subcmd = pkt[0], pkt[1:]
            if cmd == 'k':
                break

            if cmd not in commands:
                self.send('')
                self.ql.log.info("gdb> Command not supported: %s\n" %(cmd))
                continue
            self.ql.log.debug("gdb> received: %s%s" % (cmd, subcmd))
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

    def checksum(self, data):
        checksum = 0
        for c in data:
            if type(c) == str:
                checksum += (ord(c))
            else:
                checksum += c
        return checksum & 0xff

    def send(self, msg):
        """Send a packet to the GDB client"""
        if type(msg) == str:
            self.send_raw('$%s#%.2x' % (msg, self.checksum(msg)))
        else:
            self.clientsocket.send(b'$%s#%.2x' % (msg, self.checksum(msg)))
            self.netout.flush()

        self.ql.log.debug("gdb> send: $%s#%.2x" % (msg, self.checksum(msg)))

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()
