// Regression test for statx struct serialization (esp. byte order on
// big-endian guests). statx() fills a `struct statx` whose stx_mode must carry
// the S_IFDIR bit for a directory; if the struct is emitted with the wrong
// endianness the type bits are lost and the directory looks like a plain file.
//
// Build (big-endian ARM, static so it needs no rootfs loader):
//   armeb-linux-gnueabi-gcc -O2 -static -o armeb_statx statx.c
//
// Prints "DIR" when statx correctly reports the path as a directory.
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[])
{
    const char *path = (argc > 1) ? argv[1] : "/";
    struct statx stx;

    memset(&stx, 0, sizeof(stx));

    if (syscall(SYS_statx, AT_FDCWD, path, 0, STATX_BASIC_STATS, &stx) != 0) {
        perror("statx");
        return 1;
    }

    if (S_ISDIR(stx.stx_mode))
        printf("DIR\n");
    else
        printf("NOTDIR mode=%o\n", (unsigned) stx.stx_mode);

    return 0;
}
