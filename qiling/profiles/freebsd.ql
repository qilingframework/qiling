[SHELLCODER]
ram_size = 0xa00000
entry_point = 0x1000000


[OS64]
stack_address = 0x7ffffffde000
stack_size = 0x21000
load_address = 0x7ffbf0100000
interp_address = 0x7ffff7dd5000
mmap_address = 0x7fffb7dd6000


[KERNEL]
uid = 1000
gid = 1000
pid = 1996


[LOG]
# log directory output
# usage: dir = qlog
dir =
# split log file, use with multithread
split = False


[MISC]
# append string into different logs
# maily for multiple times Ql run with one file
# usage: append = test1
append =