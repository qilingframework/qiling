#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# lib/c/public/confname.h
sysconf_names = {
	1   : '_CS_PATH',          # default path to find system utilities
	2   : '_CS_HOSTNAME',      # Name of this node within the communications network
	3   : '_CS_RELEASE',       # Current release level of this implementation
	4   : '_CS_VERSION',       # Current version of this release
	5   : '_CS_MACHINE',       # Name of the hardware type on which the system is running
	6   : '__CS_ARCHITECTURE', # Name of the instructions set architechure
	7   : '_CS_HW_SERIAL',     # A serial number assiciated with the hardware
	8   : '_CS_HW_PROVIDER',   # The name of the hardware manufacturers
	9   : '_CS_SRPC_DOMAIN',   # The secure RPC domain
	11  : '_CS_SYSNAME',       # Name of this implementation of the operating system
	200 : '_CS_LIBPATH',       # default path for runtime to find standard shared objects
	201 : '_CS_DOMAIN',        # Domain of this node within the communications network
	202 : '_CS_RESOLVE',       # In memory /etc/resolve.conf
	203 : '_CS_TIMEZONE',      # timezone string (TZ style)
	204 : '_CS_LOCALE'         # locale string
}

# lib/c/public/confname.h
sysconf_consts = {
	1  : '_SC_ARG_MAX',
	2  : '_SC_CHILD_MAX',
	3  : '_SC_CLK_TCK',
	4  : '_SC_NGROUPS_MAX',
	5  : '_SC_OPEN_MAX',
	6  : '_SC_JOB_CONTROL',
	7  : '_SC_SAVED_IDS',
	8  : '_SC_VERSION',
	9  : '_SC_PASS_MAX',
	10 : '_SC_LOGNAME_MAX',
	11 : '_SC_PAGESIZE',
	12 : '_SC_XOPEN_VERSION',
	13 : '_SC_STREAM_MAX',
	14 : '_SC_TZNAME_MAX'
	# TODO: add 15 - 173
}

# lib/c/public/confname.h
pathconf_names = {
	1 : '_PC_LINK_MAX',
	2 : '_PC_MAX_CANON',
	3 : '_PC_MAX_INPUT',
	4 : '_PC_NAME_MAX',
	5 : '_PC_PATH_MAX',
	6 : '_PC_PIPE_BUF',
	7 : '_PC_NO_TRUNC',
	8 : '_PC_VDISABLE',
	9 : '_PC_CHOWN_RESTRICTED'
}

# lib/c/public/fcntl.h
file_open_flags = {
	'O_RDONLY'    : 0o0000000, # read-only
	'O_WRONLY'    : 0o0000001, # write-only
	'O_RDWR'      : 0o0000002, # read-write
	'O_APPEND'    : 0o0000010, # append
	'O_DSYNC'     : 0o0000020, # data integrity sync
	'O_SYNC'      : 0o0000040, # file integrity sync
	'O_RSYNC'     : 0o0000100, # data integrity sync
	'O_NONBLOCK'  : 0o0000200, # non-blocking
	'O_CREAT'     : 0o0000400, # file create
	'O_TRUNC'     : 0o0001000, # truncation
	'O_EXCL'      : 0o0002000, # exclusive
	'O_NOCTTY'    : 0o0004000, # no controlling terminal
	'O_CLOEXEC'   : 0o0020000, # close-on-exec
	'O_REALIDS'   : 0o0040000, # use real uid/gid instead of effectice uid/gid
	'O_LARGEFILE' : 0o0100000, # off_t can be 64 bit
	'O_ASYNC'     : 0o0200000  # async
}

# lib/c/public/share.h
file_sharing_modes = {
	0x00 : 'SH_COMPAT', # compatibility
	0x10 : 'SH_DENYRW', # deny read/write
	0x20 : 'SH_DENYWR', # deny write
	0x30 : 'SH_DENYRD', # deny read
	0x40 : 'SH_DENYNO'  # no deny
}

# lib/c/public/time.h
clock_types = {
	0 : "CLOCK_REALTIME",
	1 : "CLOCK_SOFTTIME",
	2 : "CLOCK_MONOTONIC",
	3 : "CLOCK_PROCESS_CPUTIME_ID",
	4 : "CLOCK_THREAD_CPUTIME_ID"
}

# lib/c/public/unistd.h
lseek_whence = {
	0 : "SEEK_SET", # relative to start of file
	1 : "SEEK_CUR", # relative to current position
	2 : "SEEK_END"  # relative to end of file
}

# lib/c/public/sys/conf.h
sysconf_conditions = {
	1 << 20 : "_CONF_STR", # checking for string
	2 << 20 : "_CONF_NUM"  # checking for number
}

# lib/c/public/sys/ftype.h
file_types = {
	0  : "_FTYPE_ANY",
	1  : "_FTYPE_FILE",
	2  : "_FTYPE_LINK",
	3  : "_FTYPE_SYMLINK",
	4  : "_FTYPE_PIPE",
	5  : "_FTYPE_SHMEM",
	6  : "_FTYPE_MQUEUE",
	7  : "_FTYPE_SOCKET",
	8  : "_FTYPE_SEM",
	9  : "_FTYPE_PHOTON",
	10 : "_FTYPE_DUMPER",
	11 : "_FTYPE_MOUNT",
	12 : "_FTYPE_NAME",
	13 : "_FTYPE_TYMEM"
}

# lib/c/public/sys/iomsg.h
io_connect_subtypes = {
	0 : "_IO_CONNECT_COMBINE",       # more than two iov_t
	1 : "_IO_CONNECT_COMBINE_CLOSE", # _IO_CONNECT_COMBINE with close-on-exec
	2 : "_IO_CONNECT_OPEN",
	3 : "_IO_CONNECT_UNLINK",
	4 : "_IO_CONNECT_RENAME",
	5 : "_IO_CONNECT_MKNOD",
	6 : "_IO_CONNECT_READLINK",
	7 : "_IO_CONNECT_LINK",
	8 : "_IO_CONNECT_RSVD_UNBLOCK",
	9 : "_IO_CONNECT_MOUNT"
}

# lib/c/public/sys/iomsg.h
io_connect_ioflag = {
	'_IO_FLAG_RD' : 0x01,
	'_IO_FLAG_WR' : 0x02
}

# lib/c/public/sys/iomsg.h
io_connect_eflag = {
	'_IO_CONNECT_EFLAG_DIR'    : 0x01, # path is a directory
	'_IO_CONNECT_EFLAG_DOT'    : 0x02, # last component of path is . or ..
	'_IO_CONNECT_EFLAG_DOTDOT' : 0x04  # last component is ..
}

# lib/c/public/sys/mman.h
mmap_flags = {
	'MAP_SHARED'     : 0x00000001,
	'MAP_PRIVATE'    : 0x00000002,
	'MAP_FIXED'      : 0x00000010,
	'MAP_ELF'        : 0x00000020,
	'MAP_NOSYNCFILE' : 0x00000040,
	'MAP_LAZY'       : 0x00000080,
	'MAP_STACK'      : 0x00001000,
	'MAP_BELOW'      : 0x00002000,
	'MAP_NOINIT'     : 0x00004000,
	'MAP_PHYS'       : 0x00010000,
	'MAP_NOX64K'     : 0x00020000,
	'MAP_BELOW16M'   : 0x00040000,
	'MAP_ANON'       : 0x00080000,
	'MAP_ANONYMOUS'  : 0x00080000,
	'MAP_SYSRAM'     : 0x01000000,
}

# lib/c/public/sys/neutrino.h for syscall ChannelCreate(unsigned flags)
channel_create_flags = {
	'_NTO_CHF_FIXED_PRIORITY'  : 0x0001,
	'_NTO_CHF_UNBLOCK'         : 0x0002,
	'_NTO_CHF_THREAD_DEATH'    : 0x0004,
	'_NTO_CHF_DISCONNECT'      : 0x0008,
	'_NTO_CHF_NET_MSG'         : 0x0010,
	'_NTO_CHF_SENDER_LEN'      : 0x0020,
	'_NTO_CHF_COID_DISCONNECT' : 0x0040,
	'_NTO_CHF_REPLY_LEN'       : 0x0080,
	'_NTO_CHF_STICKY'          : 0x0100,
	'_NTO_CHF_ASYNC_NONBLOCK'  : 0x0200,
	'_NTO_CHF_ASYNC'           : 0x0400,
	'_NTO_CHF_GLOBAL'          : 0x0800
}

# lib/c/public/sys/neutrino.h for syscall ConnectAttach(..., int flags)
connect_attach_flags = {
	'_NTO_COF_CLOEXEC'  : 0x0001, # close on exec
	'_NTO_COF_DEAD'     : 0x0002,
	'_NTO_COF_NOSHARE'  : 0x0040,
	'_NTO_COF_NETCON'   : 0x0080,
	'_NTO_COF_NONBLOCK' : 0x0100,
	'_NTO_COF_ASYNC'    : 0x0200,
	'_NTO_COF_GLOBAL'   : 0x0400
}

# lib/c/public/sys/stat.h
file_access = {
	0o00001 : '_S_INSEM',      # semaphore
	0o00002 : '_S_INSHD',      # shared data
	0o00003 : '_S_INMQ',       # message queue
	0o00004 : '_S_INTMO',      # typed memory
	0o40000 : '_S_QNX_SPECIAL'
}

# lib/c/public/sys/stat.h
file_stats = {
	'_S_IFIFO'  : 0x1000, # FIFO
	'_S_IFCHR'  : 0x2000, # Character special
	'_S_IFDIR'  : 0x4000, # Directory
	'_S_IFNAM'  : 0x5000, # Named file
	'_S_IFBLK'  : 0x6000, # Block special
	'_S_IFREG'  : 0x8000, # Regular
	'_S_IFLNK'  : 0xa000, # Symlink
	'_S_IFSOCK' : 0xc000  # Socket
}

# services/system/public/sys/memmsg.h
mem_ctrl_subtypes = {
	0 : "MEM_CTRL_UNMAP",
	1 : "MEM_CTRL_PROTECT",
	2 : "MEM_CTRL_SYNC",
	3 : "MEM_CTRL_LOCKALL",
	4 : "MEM_CTRL_UNLOCKALL",
	5 : "MEM_CTRL_LOCK",
	6 : "MEM_CTRL_UNLOCK",
	7 : "MEM_CTRL_ADVISE"
}

# services/system/public/sys/sysmsg.h
sysconf_subtypes = {
	0 : "_SYS_SUB_GET",
	1 : "_SYS_SUB_SET"
}
