For latest documentation, please visit https://docs.qiling.io/en/latest/ida/

## Features that have not yet been displayed in docs.qiling.io
- **Execute Selection**: You can also define function `custom_execute_selection` like other hook functions in custom script.
- **Set PC**: Set PC as the address at the cursor.
- **Deflat custom info**: See comments in the input box.
- **Remove Junk Code by Patterns**: Patch junk code like `jz/jnz` pattern in selection area.(Just support x86)
- **Nop Items without Color**: The executed code will be colored.

## Known issue:
- ollvm deflat component doesn't recognize real blocks well, such as two real blocks are linked by `jmp $5`