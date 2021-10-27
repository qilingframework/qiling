import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE

import pygame
import threading
        

class LCD:
    @classmethod
    def get_pattern(cls, ch):
        lo = (ch >> 0) & 0xf
        up = (ch >> 4) & 0xf
        with open('LCD1602A.txt') as f:
            lines = f.read().splitlines()[lo * 9 + 1: lo * 9 + 9]
            pattern = [line[up * 6 + 1: up * 6 + 6] for line in lines]

        return pattern

    @classmethod
    def make_screen(cls, infos):
        sc = []
        for info in infos:
            ps = [LCD.get_pattern(x) for x in info]            
            ln  = [''.join(p[r] for p in ps) for r in range(8)]
            sc += ln

        return sc

class LCD1602(LCD):    
    def __init__(self) -> None:
        super().__init__()

        self.rows, self.cols = 2, 16
        self.cheight, self.cwidth = 8, 5        
        
        self.cur_row, self.cur_col = 0, 0
         
        self.buf = []
        self.data = [[ord(' ') for _ in range(self.cols)] for _ in range(self.rows)]
        self.pixels = LCD.make_screen(self.data)

        self.address = 0x3f << 1

    def is_activate(self, i, j):
        return self.pixels[i][j] == '#'

    def render(self):
        size = 10
        margin, interval = size * 4, size // 2

        width  = margin * 2 + size * (self.cols * self.cwidth) + interval * (self.cols - 1)
        height = margin * 2 + size * (self.rows * self.cheight) + interval * (self.rows - 1)

        runable = True
        clock = pygame.time.Clock()
        win = pygame.display.set_mode((width, height))

        pygame.display.set_caption("LCD 1602A")

        while runable:            
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    runable = False
            
            clock.tick(60)
            pygame.draw.rect(win, "#c9f6cd", ((size, size), (width - size*2, height - size*2)), border_radius=size)
            for i in range(self.rows * self.cheight):
                for j in range(self.cols * self.cwidth):
                    x = margin + size * j + interval * (j // self.cwidth)
                    y = margin + size * i + interval * (i // self.cheight)

                    color = "#446644" if self.is_activate(i, j) else "#bbeebb"
                    pygame.draw.rect(win, color, ((x, y), (size-1, size-1)))

            pygame.display.update()            

        print('LCD quit')
        pygame.quit()

    def send(self, data):
        self.buf.append(data)

        if len(self.buf) == 4:
            up = self.buf[0] & 0xf0
            lo = self.buf[3] & 0xf0
            cmd = up | (lo >> 4)

            if self.buf[0] & 0x1:                
                if self.cur_col < 16 and self.cur_row < 2:
                    self.data[self.cur_row][self.cur_col] = cmd                
                    self.cur_col += 1
                self.pixels = LCD.make_screen(self.data)
            
            elif cmd == 0x1:
                self.data = [[ord(' ') for _ in range(self.cols)] for _ in range(self.rows)]
                self.pixels = LCD.make_screen(self.data)
            
            elif up == 0x80:
                self.cur_row, self.cur_col = 0, lo >> 4

            elif up == 0xc0:
                self.cur_row, self.cur_col = 1, lo >> 4                

            self.buf = []

    def run(self):
        threading.Thread(target=self.render).start()

def make(path, lcd):
    ql = Qiling([path],
        archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEFAULT)

    ql.hw.create('i2c1').connect(lcd)
    ql.hw.create('rcc')
    ql.hw.create('gpioa')
    ql.hw.create('gpiob')    
    
    return ql

if __name__ == "__main__":
    lcd = LCD1602()
    lcd.run()
    
    make("../rootfs/mcu/stm32f411/i2c-lcd.hex", lcd).run(count=700000)
    make("../rootfs/mcu/stm32f411/lcd-plus.hex", lcd).run(count=2000000)