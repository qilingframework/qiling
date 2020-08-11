#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


# 1. Download AC15 Firmware from https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip
# 2. unzip
# 3. binwalk -e US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin
# 4. locate squashfs-root
# 5. rm -rf webroot && mv webroot_ro webroot
#
# notes: we are using rootfs in this example, so rootfs = squashfs-root
# 

import ctypes, os, pickle, socket, sys, threading
sys.path.append("..")
from qiling import *

def nvram_listener():
    server_address = 'rootfs/var/cfm_socket'
    data = ""
    
    try:  
        os.unlink(server_address)  
    except OSError:  
        if os.path.exists(server_address):  
            raise  

    # Create UDS socket  
    sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)  
    sock.bind(server_address)  
    sock.listen(1)  
  
    while True:  
        connection, client_address = sock.accept()  
        try:  
            while True:  
                data += str(connection.recv(1024))
        
                if "lan.webiplansslen" in data:  
                    connection.send('192.168.170.169'.encode())  
                else: 
                    break  
                data = ""
        finally:  
                connection.close() 


def save_context(ql, *args, **kw):
    ql.save(cpu_context=False, snapshot="snapshot.bin")

def patcher(ql):
    br0_addr = ql.mem.search("br0".encode() + b'\x00')
    for addr in br0_addr:
        ql.mem.write(addr, b'lo\x00')


def check_pc(ql):
    print("=" * 50)
    print("[!] Hit fuzz point, stop at PC = 0x%x" % ql.reg.arch_pc)
    print("=" * 50)
    ql.emu_stop()


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug", verbose=5)
    ql.add_fs_mapper("/dev/urandom","/dev/urandom")
    ql.hook_address(save_context ,0x10930)
    ql.hook_address(patcher, ql.loader.elf_entry)
    ql.hook_address(check_pc,0x7a0cc)
    ql.run()

if __name__ == "__main__":
    nvram_listener_therad =  threading.Thread(target=nvram_listener, daemon=True)
    nvram_listener_therad.start()
    my_sandbox(["rootfs/bin/httpd"], "rootfs")
