[SHELLCODER]
# ram_size 0xa00000 is 10MB
ram_size = 0xa00000
entry_point = 0x1000000


[OS64]
stack_address = 0x7ffffffde000
stack_size = 0x30000
load_address = 0x555555554000
interp_address = 0x7ffff7dd5000
mmap_address = 0x7fffb7dd6000


[OS32]
stack_address = 0x7ff0d000
stack_size = 0x30000
load_address = 0x56555000
interp_address = 0x047ba000
mmap_address = 0x774bf000

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