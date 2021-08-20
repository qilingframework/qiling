[CODE]
# ram_size 0xa00000 is 10MB
ram_size = 0xa00000
entry_point = 0x1000000


[OS32]
stack_address = 0x7ff0d000
stack_size = 0x30000
load_address = 0x56555000
interp_address = 0x047ba000
mmap_address = 0x774bf000
syspage_address = 0xfc404000
cpupage_address = 0xfc4048d8
cpupage_tls_address = 0xfc405000
tls_data_address = 0xfc406000

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
current_path = /

[NETWORK]
# To use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time
bindtolocalhost = True
# Bind to localhost
ipv6 = False
