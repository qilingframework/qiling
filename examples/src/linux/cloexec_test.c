#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 1) {
        int fd, pid;
        char buf[20];

        fd = open("testfile", O_RDONLY);
        fcntl(fd, F_SETFD, fcntl(fd,F_GETFD) | FD_CLOEXEC);

        printf("[Main Thread] fd = %d\n",fd);

        pid = fork();
        if(pid == 0) {
            char cbuf[2];        
            if (read(fd, cbuf, 1) < 0)
                perror("[Fork Thread]  Read Fail:");
            printf("[Fork Thread] fd = %d, offset = %ld, c = '%c'\n", fd, lseek(fd, 0, SEEK_CUR), cbuf[0]);

            char fds[4];
            memset(fds, 0, sizeof fds);
            sprintf(fds, "%d", fd);

            execl("/bin/x8664_cloexec_test", "x8664_cloexec_test", fds, NULL);        
        }
        waitpid(pid, NULL, 0);
        
        if (read(fd, buf, 1) < 0)
            perror("[Main Thread]  Read Fail:");
        printf("[Main Thread] fd = %d, offset = %ld, c = '%c'\n", fd, lseek(fd, 0, SEEK_CUR), buf[0]);
    } else {
        char buf[4];
        int fd = atoi(argv[1]);        
        int r = read(fd, buf, 1);

        if (r < 0) {
            perror("[Exec Thread] Read fail\n");        
        } else {
            printf("[Exec Thread] len = %d, c = '%c'\n", r, buf[0]);
        }

        fd = open("testfile",O_RDONLY);
        if (read(fd, buf, 1) < 0) perror("[Exec Thread]  Read Fail:");
        printf("[Exec Thread] fd = %d, offset = %ld, c = '%c'\n", fd, lseek(fd, 0, SEEK_CUR), buf[0]);
    }
}