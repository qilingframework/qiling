#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
import pygame


class PyGameSSD1306Render:
    def __init__(self, width, height):
        pygame.init()

        pygame.init()

        
        self.pixel_size = 6
        self.margin = self.pixel_size * 5

        screen_width  = self.margin * 2 + width  * self.pixel_size
        screen_height = self.margin * 2 + height * self.pixel_size
        
        self.win = pygame.display.set_mode((screen_width, screen_height), flags = pygame.NOFRAME)

        pygame.draw.rect(self.win, "#111111", ((0, 0), (screen_width, screen_height)))
        pygame.draw.rect(self.win, "#000000", ((self.margin, self.margin), (screen_width-2*self.margin, screen_height-2*self.margin)))

        pygame.display.set_caption(f'SSD1306 ({width}x{height})')
        pygame.display.update()

    def check_event(self):
        pygame.event.get()

    def draw_pixel(self, x, y, color):
        pygame.draw.rect(self.win, color, (
            (self.margin + x * self.pixel_size, self.margin + y * self.pixel_size),
            (self.pixel_size - 1, self.pixel_size - 1),
        ))

    def quit(self):
        pygame.quit()
        sys.exit(0)


class PyGameSSD1306Spi(PyGameSSD1306Render):
    def __init__(self, dc=None, width=128, height=64):
        super().__init__(width, height)
        
        self.cmd = []
        self.data = []

        self.page = 0
        self.column = 0
        self.dc_port, self.dc_pin = dc

    @property
    def mode(self):
        return self.dc_port.pin(self.dc_pin)

    def send(self, data: bytes):
        if self.mode:
            self.data += data
        else:
            self.cmd  += data

    def draw(self, page, column, data):
        for bit in range(8):
            colors = ['#000000', '#ffffff']            
            self.draw_pixel(column, page * 8 + bit, colors[(data >> bit) & 1])

        pygame.display.update()

    def step(self):
        self.check_event()

        if self.cmd:
            assert len(self.data) == 0
            cmd = self.cmd.pop(0)

            if   0xb0 <= cmd <= 0xb7:
                self.page = cmd & 0xf

            elif 0x00 <= cmd <= 0x0f:
                self.column = (self.column & 0xf0) | (cmd & 0xf)

            elif 0x10 <= cmd <= 0x1f:
                self.column = (self.column & 0x0f) | ((cmd & 0xf) << 4)

        if self.data:
            for byte in self.data:
                self.draw(self.page, self.column, byte)
                self.column += 1

            self.data.clear()