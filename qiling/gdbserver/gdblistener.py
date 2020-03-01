#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# gdbserver --remote-debug  --disable-packet=threads
# documentation: according to https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol 

import struct, os
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
                if self.ql.arch == QL_X8664:
                    def reg2data(reg):
                        data = hex(int.from_bytes(struct.pack('<Q', reg), byteorder='big'))
                        data = '{:0>16}'.format(data[2:])
                        return data

                    rsp = reg2data(self.ql.uc.reg_read(UC_X86_REG_RSP))
                    rip = reg2data(self.ql.uc.reg_read(UC_X86_REG_RIP))
                    self.send('T0506:0*,;07:'+rsp+';10:'+rip+';')
                else:
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
                        s += tmp
                    for reg in registers_x8664[17:24]:
                        r = self.ql.uc.reg_read(reg)
                        tmp = hex(int.from_bytes(struct.pack('<I', r), byteorder='big'))
                        tmp = '{:0>8}'.format(tmp[2:])
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
                
                elif subcmd.startswith('ProgramSignals'):
                    self.send('OK')    

                elif subcmd.startswith('NonStop'):
                    self.send('OK')  

            def handle_D(subcmd):
                self.send('OK')
                
            def handle_q(subcmd):

                if subcmd.startswith('Supported:xmlRegisters='):    
                    if self.ql.multithread == False:
                        self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")
                        self.ida_client = True
            
                elif subcmd.startswith('Supported:multiprocess+'):
                    if self.ql.multithread == False:
                        self.send("PacketSize=1000;multiprocess+")
                        # gdb - gdbserver tcpdump
                        # self.send("PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;FastTracepoints+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+")  

                elif subcmd.startswith('Xfer:features:read:target.xml:0'):
                    if self.ql.arch == QL_X8664:
                        self.send("l<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target><architecture>i386:x86-64</architecture><osabi>GNU/Linux</osabi><xi:include href=\"64bit-core.xml\"/><xi:include href=\"64bit-sse.xml\"/><xi:include href=\"64bit-linux.xml\"/><xi:include href=\"64bit-segments.xml\"/><xi:include href=\"64bit-avx.xml\"/><xi:include href=\"64bit-mpx.xml\"/></target>")
                    
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

                elif subcmd.startswith('Xfer:threads:read::0,'):
                    xfercmd_file = os.path.join(self.ql.rootfs,"usr","share","gdb", "xfer_thread.xml")
                    f = open(xfercmd_file,"w+")
                    f.write("<threads>\r\n<thread id=\"2048\" core=\"3\" name=\"" + str(self.ql.filename[0].split('/')[-1]) + "\"/>\r\n</threads>")
                    f.close
                    f = open(xfercmd_file, 'r')
                    file_contents = f.read()
                    self.send("l" + file_contents)

                elif subcmd.startswith('Xfer:auxv:read::'):
                    # FIXME: copy from tcpdump, communication between ida and gdbserver
                    # auxvdata = unhexlify('21002a220000a0fff7ff7f000010002a2200fffb8b1f002a2006002a22000010002a2211002a220064002a220003002a22004040552a20000004002a220038002a220005002a220009002a220007002a22000050ddf7ff7f000008002a2b09002a22003047552a2000000b002a2200e803002a220c002a2200e803002a220d002a2200ec03002a220e002a2200ec03002a2217002a2b19002a2200d9e6ffffff7f00001a002a2b1f002a2200b1efffffff7f00000f002a2200e9e6ffffff7f002a2e')
                    auxvdata = b''
                    self.send(b'l' + auxvdata)  

                elif subcmd.startswith('Xfer:exec-file:read::0,3ffe'):
                    self.send("l" + str(self.ql.filename[0]))

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
                
                else:
                    if not subcmd.startswith('Supported:'):
                        self.send("")


            def handle_v(subcmd):
                
                if subcmd == 'MustReplyEmpty':
                    self.send("")
                    
                elif subcmd.startswith('File:open'):
                    binname = subcmd.split(':')[-1].split(',')[0]
                    binname = unhexlify(binname).decode(encoding='UTF-8')
                    if binname != "just probing":
                        self.fullbinpath = (os.path.join(str(os.getcwd()),binname))
                        self.ql.dprint("gdb> opening file: %s" % (binname))
                        self.send("F5")
                    else:
                        self.fullbinpath=""    
                        self.send("F0")

                elif subcmd.startswith('File:pread:5'):
 
                    offset = subcmd.split(',')[-1]
                    count = subcmd.split(',')[-2]
                    offset = ((int(offset, base=16)))
                    count = ((int(count, base=16)))

                    if os.path.exists(self.fullbinpath):
                        with open(self.fullbinpath, "rb") as f:
                            preadheader = f.read()
                        
                        if offset != 0:
                            shift_count = offset + count
                            read_offset = preadheader[offset:shift_count]
                        else:    
                            read_offset = preadheader[offset:count] 
                            
                        preadheader_len = len(preadheader)
                        read_offset = [chr(i).encode() for i in read_offset]
                        offset_escape = b''

                        for a in read_offset:
                            # 0x5d is after the targeted bytes, according to documentation
                            # note: if 0x5d location before targeted bytes, idapro will not work
                            if a == b'\x7d':
                                a = b'\x7d\x5d'
                            elif a == b'\x23':
                                a = b'\x23\x5d'
                            elif a == b'\x24':
                                a = b'\x23\x5d'        
                            elif a == b'\x2a':
                                a = b'\x2a\x5d' 
                            
                            offset_escape += a
  
                        read_offset = offset_escape 

                        if count == 1 and (preadheader_len >= offset):
                            if read_offset:
                                self.send(b'F1;' + (read_offset))
                            else:
                                self.send('F1;\x00')    
                        
                        elif count > 1:
                            # FIXME 1: copy from tcpdump, communication between ida and gdbserver, should stop at 200 and not 300
                            # FIXME 2: data form read_offset need to be run-length encoded, according to https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Binary-Data  
                            
                            #if offset == 0:
                            #    read_offset = unhexlify('7f454c46020101002a2503003e00010000003007002a2240002a2200d87d0a002a2640003800090040001d001c00060000000400000040002a220040002a220040002a2200f801002a22f801002a2208002a220003000000040000003802002a223802002a223802002a221c002a22001c002a220001002a22000100000005002a37580e002a22580e002a22000020002a210100000006000000881d002a22881d20002a21')
                            #elif offset == 100:
                            #    read_offset = unhexlify('881d20002a219902002a22b802002a22000020002a210200000006000000981d002a22981d20002a21981d20002a21f001002a22f001002a2208002a220004000000040000005402002a225402002a225402002a2244002a220044002a220004002a220050e5746404000000e80c002a22e80c002a22e80c002a2244002a220044002a220004002a220051e5746406002a4710002a2200')    
                            #elif offset == 200:
                            #    read_offset = unhexlify('52e5746404000000881d002a22881d20002a21881d20002a217802002a227802002a2201002a22002f6c696236342f6c642d6c696e75782d7838362d36342e736f2e3200040000001000000001000000474e55002a210300000002002a2200040000001400000003000000474e55005ecc71fb1f0bb25fbb6e38006ea1dbcc3150616c020000000d0000000100000006002a21200080002a22000d00000067556110002a385900000012002a2f6a00000020002a27')
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
                        if self.ida_client == True:
                            self.ql.dprint("gdb> enter vCont needed mode")
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
        
