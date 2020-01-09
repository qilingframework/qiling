#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define print_error() fprintf(stderr, "%s at line %d error.", __func__, __LINE__)

static void syscall_open() {
    char *TEST_FILENAME = "test_syscall_open.txt";
    int fd;
    int flags;
    mode_t mode;

    flags = O_CREAT | O_WRONLY;
    mode = 0644;
    fd = open(TEST_FILENAME, flags, mode);
    printf("test: open(%s, 0x%x, 0%o) return %d.\n", TEST_FILENAME, flags, mode, fd);

    if (fd == -1) {
        print_error();
        exit(1);
    }

    close(fd);
}

static void syscall_truncate() {
    char *TEST_FILENAME = "test_syscall_truncate.txt";
    int ret;
    int fd;
    int flags;
    mode_t mode;
    char buffer[] = "Hello testing";
    int len;
    off_t off;

    flags = O_CREAT | O_WRONLY;
    mode = 0644;
    fd = open(TEST_FILENAME, flags, mode);
    if (fd == -1) {
        print_error();
        exit(1);
    }
    len = sizeof(buffer);
    ret = write(fd, buffer, len);
    if (ret != len) {
	print_error();
        exit(1);
    }
    close(fd);

    off = 0;
    ret = truncate(TEST_FILENAME, off);
    printf("test: truncate(%s, 0x%x) return %d.\n", TEST_FILENAME, off, ret);
    if (ret == -1) {
        print_error();
        exit(1);
    }

    /* check the file has been trucated or not. */
    /* stat(), check the st_size. should be 0*/
}

static void syscall_ftruncate() {
    char *TEST_FILENAME = "test_syscall_ftruncate.txt";
    int ret;
    int fd;
    int flags;
    mode_t mode;
    int len=0x10;

    flags = O_CREAT | O_WRONLY;
    mode = 0644;
    fd = open(TEST_FILENAME, flags, mode);

    if (fd == -1) {
        print_error();
        exit(1);
    }

    ret = ftruncate(fd, len);
    printf("test: ftruncate(%d, 0x%x) return %d.\n", fd, len, ret);
    close(fd);

    if (ret == -1) {
        print_error();
        exit(1);
    }

    /* check the file has been trucated or not. */
    /* stat(), check the st_size. should be 0x10*/
}

static void syscall_unlink() {
    char *TEST_FILENAME = "test_syscall_unlink.txt";
    int ret;
    int fd;
    int flags;
    mode_t mode;

    flags = O_CREAT | O_WRONLY;
    mode = 0644;
    fd = open(TEST_FILENAME, flags, mode);

    if (fd == -1) {
        print_error();
        exit(1);
    }

    close(fd);
    ret = unlink(TEST_FILENAME);
    printf("test: unlink(%s) return %d.\n", TEST_FILENAME, ret);
    
    if (ret == -1) {
        print_error();
        exit(1);
    }
}



int main(int argc, const char **argv) {

    syscall_open();

    syscall_truncate();
    
    syscall_ftruncate();

    syscall_unlink();

    return 0;
}
