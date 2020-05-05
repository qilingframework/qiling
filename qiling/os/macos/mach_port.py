#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# reference to 《Mac OS X and IOS Internals: To the Apple's Core》
from struct import pack, unpack
from qiling.const import *

# define in kernel osfmk/mach/message.h
# mach_msg_header_t:
#   mach_msg_bits_t	msgh_bits;                  unsigned int 
#   mach_msg_size_t	msgh_size;                  4 bytes
#   mach_port_t		msgh_remote_port;           4 bytes
#   mach_port_t		msgh_local_port;            4 bytes
#   mach_port_name_t	msgh_voucher_port;      4 bytes
#   mach_msg_id_t		msgh_id;                4 bytes
class MachMsgHeader():

    def __init__(self, ql):
        self.header_size = 24
        self.ql = ql
        self.msgh_bits = None
        self.msgh_size = None
        self.msgh_remote_port = None
        self.msgh_local_port = None
        self.msgh_voucher_port = None
        self.msgh_id = None
    
    def read_header_from_mem(self, addr):
        self.msgh_bits = unpack("<L", self.ql.mem.read(addr, 0x4))[0]
        self.msgh_size = unpack("<L", self.ql.mem.read(addr + 0x4, 0x4))[0]
        self.msgh_remote_port = unpack("<L", self.ql.mem.read(addr + 0x8, 0x4))[0]
        self.msgh_local_port = unpack("<L", self.ql.mem.read(addr + 0xc, 0x4))[0]
        self.msgh_voucher_port = unpack("<L", self.ql.mem.read(addr + 0x10, 0x4))[0]
        self.msgh_id = unpack("<L", self.ql.mem.read(addr + 0x14, 0x4))[0]
        # print("size !!!!! {}".format(self.msgh_size))

    # def __str__(self):
    #     return "[MachMsg] bits :{}, size:{}, remote port:{}, local port:{}, voucher port:{}, id:{}".format(
    #         self.msgh_bits,
    #         self.msgh_size,
    #         self.msgh_remote_port,
    #         self.msgh_local_port,
    #         self.msgh_voucher_port,
    #         self.msgh_id,
    #     )


# Mach message Class 
# mach msg: header + content + trailer
class MachMsg():
    def __init__(self, ql):
        self.ql = ql
        self.header = MachMsgHeader(self.ql)
        self.content = b''
        self.trailer = b''
        pass
    
    def read_msg_from_mem(self, addr, size):
        self.header = self.read_msg_header(addr, size)
        # between header and content is 4 byte \x00
        self.content = self.read_msg_content(addr + self.header.header_size, size - self.header.header_size)

    def write_msg_to_mem(self, addr):
        self.ql.mem.write(addr, pack("<L", self.header.msgh_bits))
        self.ql.mem.write(addr + 0x4, pack("<L", self.header.msgh_size))
        self.ql.mem.write(addr + 0x8, pack("<L", self.header.msgh_remote_port))
        self.ql.mem.write(addr + 0xc, pack("<L", self.header.msgh_local_port))
        self.ql.mem.write(addr + 0x10, pack("<L", self.header.msgh_voucher_port))
        self.ql.mem.write(addr + 0x14, pack("<L", self.header.msgh_id))
        if self.content:
            self.ql.mem.write(addr + 0x18, self.content)
        if self.trailer:
            self.ql.mem.write(addr + 0x18 + len(self.content), self.trailer)

    def read_msg_header(self, addr, size):
        header = MachMsgHeader(self.ql)
        header.read_header_from_mem(addr)
        header.msgh_size = size
        return header

    def read_msg_content(self, addr, size):
        self.ql.dprint(D_INFO, "0x{:X}, {}".format(addr, size))
        return self.ql.mem.read(addr, size)


# Mach Port Class 
# not Finished
class MachPort():

    def __init__(self, port_name):
        self.name = port_name
        pass


# Mach Port Manager : 
#   1. handle mach msg
#   2. register some Host Port

class MachPortManager():

    def __init__(self, ql, my_port):
        self.ql = ql
        self.host_port = MachPort(0x303)
        self.clock_port = MachPort(0x803)
        self.semaphore_port = MachPort(0x903)
        self.special_port = MachPort(0x707)
        self.my_port = my_port

    def deal_with_msg(self, msg, addr):

        if msg.header.msgh_id == 200:
            # host info
            out_msg = self.ql.os.macho_host_server.host_info(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 206:
            out_msg = self.ql.os.macho_host_server.host_get_clock_service(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 3418:
            out_msg = self.ql.os.macho_task_server.semaphore_create(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 3409:
            out_msg = self.ql.os.macho_task_server.get_special_port(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        else:
            self.ql.nprint("Error Mach Msgid {} can not handled".format(msg.header.msgh_id))
            raise Exception("Mach Msgid Not Found")

        self.ql.dprint(D_INFO, "Reply-> Header: {}, Content: {}".format(out_msg.header, out_msg.content))

    def get_thread_port(self, MachoThread):
        return MachoThread.port.name

# XNU define struct :
# struct mach_msg_overwrite_trap_args {
# 	PAD_ARG_(user_addr_t, msg);                     addr length
# 	PAD_ARG_(mach_msg_option_t, option);            int
# 	PAD_ARG_(mach_msg_size_t, send_size);           unsigned int
# 	PAD_ARG_(mach_msg_size_t, rcv_size);            unsigned int
# 	PAD_ARG_(mach_port_name_t, rcv_name);           unsigned int 
# 	PAD_ARG_(mach_msg_timeout_t, timeout);          unsigned int
# 	PAD_ARG_(mach_msg_priority_t, override);        unsigned int
# 	PAD_ARG_8
# 	PAD_ARG_(user_addr_t, rcv_msg);  /* Unused on mach_msg_trap */  addr length
# };
