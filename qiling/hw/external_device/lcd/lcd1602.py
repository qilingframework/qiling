#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
import pygame

from qiling.hw.external_device.lcd.const import lcd1602_table


class PyGameLCD1602Render:
    def __init__(self, caption="LCD 1602"):
        self.unit = 10
        self.letter_size = (5, 8)
        self.text_scale = (16, 2)        
        self.space, self.gap = self.unit * 4, self.unit // 2

        size = (
            width  := 
                2 * self.space + 
                self.gap  * self.text_scale[0] - self.gap +
                self.unit * self.text_scale[0] * self.letter_size[0],
            height := 
                2 * self.space + 
                self.gap  * self.text_scale[1] - self.gap + 
                self.unit * self.text_scale[1] * self.letter_size[1],
        )

        
        pygame.init()
        self.win = pygame.display.set_mode(size, flags = pygame.NOFRAME)
        
        pygame.display.set_caption(caption)

        pygame.draw.rect(
            self.win, "#c9f6cd",
            ((self.unit, self.unit), (width - self.unit*2, height - self.unit*2)),
            border_radius=self.unit
        )

        row_num = self.letter_size[1] * self.text_scale[1]
        col_num = self.letter_size[0] * self.text_scale[0]
        
        for i in range(row_num):
            for j in range(col_num):
                self.draw_pixel(i, j, False)    

        pygame.display.update()

    def draw_pixel(self, i, j, activate=True):
        x = self.space + self.unit * j + self.gap * (j // self.letter_size[0])
        y = self.space + self.unit * i + self.gap * (i // self.letter_size[1])

        color = "#446644" if activate else "#bbeebb"
        pygame.draw.rect(self.win, color, ((x, y), (self.unit-1, self.unit-1)))

    def check_event(self):
        pygame.event.get()    

    def quit(self):
        pygame.quit()
        sys.exit(0)

class PyGameLCD1602(PyGameLCD1602Render):
    def __init__(self, address=0x3f):
        super().__init__()
        
        
        self.buffer = []
        self.pos = (0, 0)
        self.address = address * 2        

        self.generate_pattern_map()

    def generate_pattern_map(self):
        self.patterns = [0] * 256
        lines = lcd1602_table.strip().splitlines()

        for up in range(16):
            for lo in range(16):
                pattern = []
                for line in lines[lo*9 + 1: lo*9 + 9]:
                    pattern.append([chr == '#' for chr in line[up * 6 + 1: up * 6 + 6]])
                self.patterns[up << 4 | lo] = pattern

    def set_value(self, row, col, value):
        pattern = self.patterns[value]

        for i in range(self.letter_size[1]):
            for j in range(self.letter_size[0]):
                self.draw_pixel(
                    i + row * self.letter_size[1], 
                    j + col * self.letter_size[0], 
                    pattern[i][j]
                )

    def execute(self, command):
        a, b, c, d = command

        up = a & 0xf0
        lo = c & 0xf0

        cmd = up | (lo >> 4)

        if a & 0x1:                
            row, col = self.pos
            self.set_value(row, col, cmd)
            self.pos = (row, col + 1)
            
            pygame.display.update()

        elif cmd == 0x1:
            self.pos = (0, 0)
            for x in range(self.text_scale[1]):
                for y in range(self.text_scale[0]):
                    self.set_value(x, y, ord(' '))
    
            pygame.display.update()

        elif up == 0x80:
            self.pos = (0, lo >> 4)                    

        elif up == 0xc0:
            self.pos = (1, lo >> 4)                    

    def send(self, data: bytes):
        self.buffer += data

    def step(self):
        self.check_event()

        if len(self.buffer) >= 4:
            self.execute(self.buffer[:4])
            self.buffer = self.buffer[4:]
