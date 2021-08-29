#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from rich import box
from rich import print as rprint
from rich.align import Align
from rich.console import Console, RenderGroup
from rich.layout import Layout
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table


console = Console()

def hexdump(src, length=16, sep='.', minrows=8, start=0, prevsrc="", to_list=False):
    """
    @brief Return {src} in hex dump.
    """
    txt = lambda c: chr(c) if 0x20 <= c < 0x7F else "."

    result = []
    result.append('           00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |  [ --ascii--]')
    result.append('')
    rows = []

    for i in range(16):
        subSrc = src[2 * (start * 16 + i * 16):2 * (start * 16 + i * 16) + length * 2]
        hexa = ''
        text = ''
        if len(subSrc) > 0:
            for h in range(0, len(subSrc), 2):
                if h == length:
                    hexa += ' '
                byte = int(subSrc[h:h + 2], 16)

                # Check if it changed from op before
                changed = False
                if prevsrc is not None:
                    index = 2 * (start + i) * 16 + h
                    if index + 2 > len(prevsrc):
                        changed = True
                    elif int(prevsrc[index:index + 2], 16) != byte:
                        changed = True

                if changed:
                    hexa += "{:02x} ".format(byte)
                else:
                    hexa += "{:02x} ".format(byte)
                text += txt(byte)

        rows.append('{:08x}:  {:<49} | {:<16} '.format(16 * (start + i), hexa, text))
        if len(rows) == minrows:
            break
    result.extend(rows)
    if to_list:
        return result
    return '\n'.join(result)

def stackdump(src, length=16, minrows=8, start=0, to_list=False):
    result = []

    for i in range(start, min(minrows, len(src))):
        v_type = src[i][0]
        value = src[i][1]
        if v_type is bytes:
            val = int(value.hex(), 16)
        elif v_type is int:
            val = value
        else:
            val = int(value[2:], 16)
        
        if i < len(src):
            stackvalue = "  {:02} : {:.>64x}".format(i, val)
        else:
            stackvalue = "  {:02} : {:64}".format(i, "")

        result.append(stackvalue)

    if to_list:
        return result
    return '\n'.join(result)


def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header", ratio=1),
        Layout(name="main", ratio=15),
        Layout(name="footer", ratio=4),
    )
    layout["main"].split_row(
        Layout(name="body", ratio=10),
        Layout(name="side", ratio=15)
    )
    layout["side"].split(Layout(name="box1", minimum_size=15, ratio=10), Layout(name="box2", ratio=10), Layout(name="box3", ratio=15))
    return layout

def make_disasm_panel(debugger) -> Panel:
    code = ''
    front_num = 10
    pc = debugger.executor.vm_context.code.pc + 1
    current_insn_index = 0

    for i, k in enumerate(debugger.executor.disasm_dict): 
        if k >= pc:
            current_insn_index = i
            break

    begin_index = max(current_insn_index-front_num, 0)
    show_disasm_list = list(debugger.executor.disasm_dict.values())[begin_index:]
    index = 0
    for insn in show_disasm_list:
        if index >= 100:
            break
        if insn.pc == pc:
            code += f'[b red][{insn.pc}] {insn.byte} {insn.mnemonic} {insn.imm_op}[/b red]\n'
        else:
            code += f'[b blue][{insn.pc}] {insn.byte} {insn.mnemonic} {insn.imm_op}[/b blue]\n'
        index += 1

    # syntax = Syntax(code, "default", line_numbers=False)
    return Panel(code, border_style="green", title="[b red]Disassembly")

def make_memory_panel(debugger) -> Panel:
    addr = 0
    mem_bytes = debugger.executor.vm_context.memory_read_bytes(0, 16*8)
    byte = ''.join(['%02X' % b for b in mem_bytes])
    res = hexdump(byte, start=int(addr), to_list=True)
    mem_table = Table.grid(padding=0)
    
    for i in res:
        mem_table.add_row(i)

    memory_panel = Panel(
        Align.center(
            RenderGroup('', "\n", Align.center(mem_table)),
            vertical="top",
        ),
        box=box.ROUNDED,
        padding=(0, 1),
        title="[b red]Memory",
        border_style="bright_blue",
    )
    return memory_panel

def make_stack_panel(debugger) -> Panel:
    stack_table = stackdump(debugger.executor.vm_context._stack.values)

    stack_panel = Panel(
        Align.center(stack_table),
        box=box.ROUNDED,
        padding=(1, 1),
        title="[b red]Stack",
        border_style="bright_blue",
    )
    return stack_panel

def make_info_panel(debugger) -> Layout:
    info_layout = Layout(name='Info')
    info_layout.split_row(
        Layout(name='runtime_state'),
        Layout(name='world_state')
    )

    pc = debugger.executor.vm_context.code.pc + 1
    insn = debugger.executor.disasm_dict[pc]
    opcode = insn.byte
    mnemonic = insn.mnemonic
    msg = debugger.executor.vm_context.msg
    info_table = Table(box=box.SIMPLE)
    info_table.grid(padding=1)
    info_table.add_column('Key', justify="middle", style="cyan", no_wrap=True)
    info_table.add_column("Value", justify="middle", style="magenta")
    info_table.add_row('PC', f'{str(pc)} ({hex(pc)})')
    info_table.add_row('Opcode', f'{int(opcode[2:], 16)} ({opcode})')
    info_table.add_row('Mnemonic', f'{mnemonic}')
    info_table.add_row('', '')
    info_table.add_row('Sender', f'0x{msg.sender.hex()}')
    if msg.to:
        info_table.add_row('To', f'0x{msg.to.hex()}')
    elif msg.storage_address:
        info_table.add_row('To', f'0x{msg.storage_address.hex()}')
    elif msg.code_address:
        info_table.add_row('To', f'0x{msg.code_address.hex()}')
    info_table.add_row('Gas Price', str(msg.gas_price))
    info_table.add_row('Nonce', str(debugger.executor.vm_context.msg.depth))

    info_panel = Panel(
        info_table,
        box=box.ROUNDED,
        title="[b red]Runtime State",
        border_style="bright_blue",
    )


    state = debugger.executor.vm_context.state
    world_state_table = Table(box=box.SIMPLE)
    world_state_table.grid(padding=1)
    world_state_table.add_column('Key', justify="middle", style="cyan", no_wrap=True)
    world_state_table.add_column("Value", justify="middle", style="magenta")
    world_state_table.add_row('coinbase', f'{state.coinbase.hex()}')
    world_state_table.add_row('timestamp', f'{state.timestamp}')
    world_state_table.add_row('block_number', f'{state.block_number}')
    world_state_table.add_row('difficulty', f'{state.difficulty}')
    world_state_table.add_row('gas_limit', f'{state.gas_limit}')


    world_state_panel = Panel(
        world_state_table,
        box=box.ROUNDED,
        title="[b red]World State",
        border_style="bright_blue",
    )

    info_layout["runtime_state"].update(info_panel)
    info_layout["world_state"].update(world_state_panel)

    return info_layout

def make_funcsign_panel(debugger) -> Panel:
    funcsign_table = Table(box=box.SIMPLE)
    funcsign_table.grid(padding=2)
    funcsign_table.add_column('Xref', justify="middle", style="cyan", no_wrap=True)
    funcsign_table.add_column("Sign", justify="middle", style="magenta")
    funcsign_table.add_column("Name", justify="middle", style="magenta")
    funcsign_table.add_column("Prefered_name", justify="middle", style="magenta")
    funcsign_table.add_column("Most_prefered_name", justify="middle", style="magenta")

    for i in debugger.func_sign:
        prefered_name = ' '.join(i.prefered_name)
        most_prefered_name = ' '.join(i.most_prefered_name)
        funcsign_table.add_row(str(i.xref), str(i.sign), i.name, prefered_name, most_prefered_name)

    funcsign_panel = Panel(
        funcsign_table,
        box=box.ROUNDED,
        padding=(1, 1),
        title="[b red]Function Sign",
        border_style="bright_blue",
    )
    return funcsign_panel

def main_output(debugger):
    console.clear()
    # title_padding = Padding('', (2, 1))
    # rprint(title_padding)
    # console.rule('EVM Dynamic Debugger')
    header_padding = Panel('', box=box.MINIMAL)  

    layout = make_layout()
    layout["header"].update(header_padding)
    layout["body"].update(make_disasm_panel(debugger))
    layout["box1"].update(make_memory_panel(debugger))    
    layout["box2"].update(make_stack_panel(debugger))
    layout["box3"].update(make_funcsign_panel(debugger))
    layout["footer"].update(make_info_panel(debugger))

    # print(layout)
    return layout
