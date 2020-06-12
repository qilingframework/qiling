[OS64]
heap_address = 0x500000000
heap_size = 0x5000000
stack_address = 0x7ffffffde000
stack_size = 0x40000
image_address  = 0x400000
dll_address = 0x7ffff0000000
entry_point = 0x140000000


[OS32]
heap_address = 0x5000000
heap_size = 0x5000000
stack_address = 0xfffdd000
stack_size = 0x21000
image_address  = 0x400000
dll_address  = 0x10000000
entry_point = 0x40000  


[SHELLCODER]
# ram_size 0xa00000 is 10MB
ram_size = 0xa00000
entry_point = 0x1000000


[KERNEL]
pid = 1996
parent_pid = 0
shell_pid = 10

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
automatize_input = False



[SYSTEM]
# Major Minor ProductType
majorVersion = 10
minorVersion = 0
productType = 1
language = 1093
VER_SERVICEPACKMAJOR = 0
computername = qilingpc
permission = root

[PROCESSES]
# process active in our env -> pid
csrss.exe = 1239

[USER]
username = Qiling
language = 1093


[PATH]
systemdrive = C:\
windir = Windows\


[REGISTRY]
registry_diff = registry_diff.json


[HARDWARE]
number_processors = 5

[VOLUME]
name = Volume1
serial_number = 3224010732
type = NTFS
sectors_per_cluster = 10
bytes_per_sector = 512
number_of_free_clusters = 12345
number_of_clusters = 65536


[NETWORK]
dns_response_ip = 10.20.30.40
