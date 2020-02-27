#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct, os
from qiling.gdbserver import qldbg
from qiling.gdbserver.reg_table import *

GDB_SIGNAL_TRAP = 5


def checksum(data):
    checksum = 0
    for c in data:
        checksum += ord(c)
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
        self.ida_client     = False
        self.qldbg          = qldbg.Qldbg()
        self.qldbg.initialize(self.ql, exit_point=exit_point, mappings=mappings)
        if self.ql.ostype in (QL_LINUX, QL_FREEBSD):
            self.qldbg.bp_insert(self.ql.elf_entry)
        else:
            self.qldbg.bp_insert(self.ql.entry_point)

    def close(self):
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()

    def run(self):
        while self.receive() == 'Good':
            pkt = self.last_pkt
            self.send_raw('+')

            def handle_qmark(subcmd):
                # 0506:0*,;07:b0e4f*"7f0* ;10:9060ddf7ff7f0* ;thread:4c2b;core:3;#40
                # self.send('S0506:0*,;07:b0e4f*\"7f0* ;10:9060ddf7ff7f0* ;thread:4c2b;core:1;')
                self.send(('S%.2x' % GDB_SIGNAL_TRAP))


            def handle_c(subcmd):
                self.qldbg.resume_emu(self.ql.uc.reg_read(get_reg_pc(self.ql.arch)))
                self.send(('S%.2x' % GDB_SIGNAL_TRAP))


            handle_C = handle_c


            def handle_g(subcmd):
                s = ''
                if self.ql.arch == QL_X86:
                    for reg in registers_x86[:17]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = hex(int.from_bytes(struct.pack('<I', r), byteorder='big'))
                        tmp = '{:0>8}'.format(tmp[2:])
                        s += tmp
                elif self.ql.arch == QL_X8664:
                    for reg in registers_x8664[:17]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = hex(int.from_bytes(struct.pack('<Q', r), byteorder='big'))
                        tmp = '{:0>16}'.format(tmp[2:])
                        #self.ql.dprint(tmp)
                        s += tmp
                    for reg in registers_x8664[17:24]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = hex(int.from_bytes(struct.pack('<I', r), byteorder='big'))
                        tmp = '{:0>8}'.format(tmp[2:])
                        #self.ql.dprint(tmp)
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
                        reg_value = hex(int.from_bytes(struct.pack('<I', reg_value), byteorder='big'))
                        reg_value = '{:0>8}'.format(reg_value[2:])
                    elif self.ql.arch == QL_X8664:
                        if reg_index <= 32:
                            reg_value = self.ql.uc.reg_read(registers_x8664[reg_index-1])
                        else:
                            reg_value = 0
                        if reg_index <= 17:
                            reg_value = hex(int.from_bytes(struct.pack('<Q', reg_value), byteorder='big'))
                            reg_value = '{:0>16}'.format(reg_value[2:])
                        elif 17 < reg_index:
                            reg_value = hex(int.from_bytes(struct.pack('<I', reg_value), byteorder='big'))
                            reg_value = '{:0>8}'.format(reg_value[2:])
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
                elif self.ql.arch == QL_X8664:
                    if reg_index <= 17:
                        reg_data = int(reg_data, 16)
                        reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                        self.ql.uc.reg_write(registers_x8664[reg_index], reg_data)
                    else:
                        reg_data = int(reg_data[:8], 16)
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                        self.ql.uc.reg_write(registers_x8664[reg_index], reg_data)
                self.ql.nprint("gdb> write to register %x with %x" %(registers_x8664[reg_index],reg_data))        
                self.send('OK')


            def handle_Q(subcmd):
                if subcmd.startswith('StartNoAckMode'):
                    self.send('OK')
                elif subcmd.startswith('DisableRandomization'):
                    self.send('OK')


            def handle_q(subcmd):
                if subcmd.startswith('Supported:xmlRegisters='):
                    self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")
                    self.ida_client = True
                
                elif subcmd.startswith('Supported:multiprocess+'):
                    self.send("PacketSize=1000;multiprocess+")
                    #self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;FastTracepoints+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")  

                elif subcmd.startswith('Xfer:features:read:target.xml:0'):
                    if self.ql.arch == QL_X8664 and self.ida_client:
                        self.send("l<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target><architecture>i386:x86-64</architecture><osabi>GNU/Linux</osabi><xi:include href=\"64bit-core.xml\"/><xi:include href=\"64bit-sse.xml\"/><xi:include href=\"64bit-linux.xml\"/><xi:include href=\"64bit-segments.xml\"/><xi:include href=\"64bit-avx.xml\"/><xi:include href=\"64bit-mpx.xml\"/></target>")
                    else:    
                        self.send('l')

                elif subcmd.startswith('Xfer:features:read:'):
                    if self.ql.arch == QL_X8664:
                        xfercmd_file = subcmd.split(':')[3]
                        xfercmd_file = os.path.join(self.ql.rootfs,"usr","share","gdb", xfercmd_file)
                        if os.path.exists(xfercmd_file):
                            f = open(xfercmd_file, 'r')
                            file_contents = f.read()
                            self.send("l" + file_contents)
                        else:
                            self.ql.nprint("gdb> xml file not found: %s" % (xfercmd_file))
                            exit(1)

                elif subcmd.startswith('Xfer:threads:read::0,3ffe'):
                    xfercmd_file = os.path.join(self.ql.rootfs,"usr","share","gdb", "xfer_thread.xml")
                    f = open(xfercmd_file,"w+")
                    f.write("<threads>\r\n<thread id=\"651b\" core=\"3\" name=\"" + str(self.ql.filename[0].split('/')[-1]) + "\"/>\r\n</threads>")
                    f.close
                    f = open(xfercmd_file, 'r')
                    file_contents = f.read()
                    self.send("l" + file_contents)

                elif subcmd == 'Xfer:auxv:read::0,1000':
                      self.send('l')  

                elif subcmd.startswith('Xfer:exec-file:read::0,3ffe'):
                    self.send("l" + str(self.ql.filename[0]))
                
                elif subcmd == "Attached":
                    self.send("")
                
                elif subcmd.startswith("C"):
                    self.send("")
                
                elif subcmd.startswith("L:"):
                    self.send("M001")
                
                elif subcmd == "fThreadInfo":
                    self.send("m1")
                
                elif subcmd == "sThreadInfo":
                    self.send("l")
                
                elif subcmd.startswith("TStatus"):
                    self.send("")
                
                elif subcmd == "Symbol":
                    self.send("OK")
                
                elif subcmd == "Offsets":
                    self.send("Text=0;Data=0;Bss=0")
                
                else:
                    if not subcmd.startswith('Supported:'):
                        self.send("")


            def handle_v(subcmd):
                
                if subcmd == 'MustReplyEmpty':
                    self.send("")
                    
                elif subcmd.startswith('File:open'):
                    self.send("F5")

                elif subcmd.startswith('File:pread:5,1,'):
                    mode_file_pread = subcmd.split(',')[-1]
                    if mode_file_pread == "fff":
                        self.send("F1;")
                    if mode_file_pread == "1fff":
                        self.send("F1")                        
                    if mode_file_pread == "7ff":
                        self.send("F1")
                    if mode_file_pread == "3ff":
                        self.send("F0")
                    if mode_file_pread == "1ff":
                        self.send("F1")                                                                        
                    if mode_file_pread == "ff":
                        self.send("F1")                                                                        
                    if mode_file_pread == "7f":
                        self.send("F1")                                                                        
                    if mode_file_pread == "3f":
                        self.send("F1")                                                                        
                    if mode_file_pread == "1f":
                        self.send("F1")                                                                        
                    if mode_file_pread == "7":
                        self.send("F1")                                                                        
                    if mode_file_pread == "3":
                        self.send("F1")                                                                        
                    if mode_file_pread == "1":
                        self.send("F1")                                                                        
                    if mode_file_pread == "0":
                        self.send("F1")                                                                        

                elif subcmd.startswith('File:close'):
                    self.send("F0")


                elif subcmd.startswith('Kill'):
                    self.send('OK')
                    exit(1)

                elif subcmd.startswith('Cont'):
                    self.ql.dprint("gdb> Cont command received: %s" % subcmd)
                    if subcmd == 'Cont?':
                        # if self.ida_client == True:
                        #     self.ql.dprint("gdb> enter vCont needed mode")
                        #     self.send('vCont;c;C;s;S')
                        # else:    
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
        self.send_raw('$%s#%.2x' % (msg, checksum(msg)))
        self.ql.dprint("gdb> send: $%s#%.2x" % (msg, checksum(msg)))


    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()
