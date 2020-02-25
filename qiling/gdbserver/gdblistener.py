#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct
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
        self.sup            = True
        self.tst            = True
        self.f9_count       = 0
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
                self.send(('S%.2x' % GDB_SIGNAL_TRAP))

            def handle_c(subcmd):
                if self.f9_count == 0:
                    handle_s(subcmd)
                else:    
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

            def handle_p(subcmd):  # $p21#d3
                reg_index = int(subcmd, 16)
                reg_value = None
                self.ql.dprint("gdb> register index: %i" % (reg_index))
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
                reg_index = int(reg_index)
                reg_data = int(reg_data, 16)
                if self.ql.arch == QL_X86:
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                    self.ql.uc.reg_write(registers_x86[reg_index], reg_data)
                elif self.ql.arch == QL_X8664:
                    if reg_index <= 17:
                        reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                        self.ql.uc.reg_write(registers_x8664[reg_index], reg_data)
                    else:
                        reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                        self.ql.uc.reg_write(registers_x8664[reg_index], reg_data)
                self.send('OK')

            def handle_q(subcmd):
                if subcmd.startswith('Supported:') and self.sup:
                    self.send("PacketSize=1000;multiprocess+")
                    self.sup = False
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
                elif subcmd.startswith("TStatus") and self.tst:
                    self.send("")
                    self.tst = False
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
                    pass
                if subcmd.startswith('Kill'):
                    self.send('OK')
                    exit(1)
                elif subcmd.startswith('Cont'):
                    if subcmd == 'Cont?':
                        self.send('vCont;c;C;s;S')
                    else:
                        subcmd = subcmd.split(';')
                        if subcmd[1] in ('c', 'C05'):
                            self.qldbg.resume_emu(self.ql.uc.reg_read(get_reg_pc(self.ql.arch)))
                            self.send('S%.2x' % GDB_SIGNAL_TRAP)
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
                self.f9_count = 1

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

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()
