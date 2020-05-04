[OS64]
EMU_END = 0xffffffffffffffff

[OS32]
EMU_END = 0x8fffffff

[X8664]
head_base_addr = 0x500000000
head_base_size = 0x5000000
stackaddress = 0x7ffffffde000
stacksize = 0x40000
default_image_base = 0x400000
dll_base_addr = 0x7ffff0000000
entry_point = 0x140000000

[X86]
head_base_addr = 0x5000000
head_base_size = 0x5000000
stackaddress = 0xfffdd000
stacksize = 0x21000
default_image_base = 0x400000
dll_base_addr = 0x10000000
entry_point = 0x40000  

[SHELLCODER]
ram_size = 0xa00000
entry_point = 0x1000000


[SYSTEM]
# Major Minor ProductType
majorVersion = 10
minorVersion = 0
productType = 1
language = 1093
VER_SERVICEPACKMAJOR = 0
computername = qilingpc
permission = root

[USER]
username = Qiling
language = 1093

[PATH]
systemdrive = C:\
windir = Windows\

[REGISTRY]
registry_diff = registry_diff.json

[VOLUME]
serial_number = 3224010732
type = NTFS

sectors_per_cluster = 10
bytes_per_sector = 512
number_of_free_clusters = 12345
number_of_clusters = 65536

[NETWORK]
dns_response_ip = 10.20.30.40
