#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import pty
import ctypes
import select
import termios
import threading


class Termios(ctypes.Structure):
    _fields_ = [
        ('c_iflag' , ctypes.c_int32),     # input flags
        ('c_oflag' , ctypes.c_int32),     # output flags
        ('c_cflag' , ctypes.c_int32),     # control flags
        ('c_lflag' , ctypes.c_int32),     # local flags
        ('c_cc'    , ctypes.c_char * 32), # control chars
        ('c_ispeed', ctypes.c_int32),     # input speed
        ('c_ospeed', ctypes.c_int32),     # output speed
    ]

    def __init__(self, fd):
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = termios.tcgetattr(fd)
        super().__init__(
            c_iflag = iflag,
            c_oflag = oflag,
            c_cflag = cflag,
            c_lflag = lflag,
            c_cc    = b''.join([bytes(c) for c in cc]),
            c_ispeed = ispeed,
            c_ospeed = ospeed,
        )
    
    def getattr(self):
        return [self.c_iflag, self.c_oflag, self.c_cflag, self.c_lflag, self.c_ispeed, self.c_ospeed, list(self.c_cc.ljust(32, b'\0'))]

    def setattr(self, fd):
        termios.tcsetattr(fd, termios.TCSANOW, self.getattr())    

class QlSerial:
    def __init__(self, ql, baudrate=115200):        
        self.ql = ql
        self.baudrate = baudrate

        self.master_x, self.slave_x = QlSerial.create_pty(baudrate)
        self.master_y, self.slave_y = QlSerial.create_pty(baudrate)

        self.started = False

    def start(self):
        def daemon():
            while True:
                rlist, _, _ = select.select([self.master_x, self.master_y], [], [])
                if self.master_x in rlist:
                    os.write(self.master_y, os.read(self.master_x, 0x100))
                if self.master_y in rlist:
                    os.write(self.master_x, os.read(self.master_y, 0x100))
                select.select([self.master_x, self.master_y], [self.master_x, self.master_y], [])
        
        if not self.started:
            self.started = True
            threading.Thread(target=daemon).start()

    @classmethod
    def create_pty(cls, baudrate):
        master, slave = pty.openpty()
        
        t = Termios(master)

        ## baudrate
        speed = getattr(termios, f'B{baudrate}', termios.B115200)
        t.c_ispeed = speed
        t.c_ospeed = speed

        ## raw mode
        t.c_iflag &= ~(termios.IGNBRK|termios.BRKINT|termios.PARMRK|termios.ISTRIP|termios.INLCR|termios.IGNCR|termios.ICRNL|termios.IXON)
        t.c_oflag &= ~termios.OPOST
        t.c_cflag &= ~(termios.ECHO|termios.ECHONL|termios.ICANON|termios.ISIG|termios.IEXTEN)
        t.c_lflag &= ~(termios.CSIZE|termios.PARENB)
        t.c_lflag |= termios.CS8
        t.setattr(master)

        return master, slave
