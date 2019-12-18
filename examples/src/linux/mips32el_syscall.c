#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, const char **argv)
{
    FILE *pFile;
    int fd;

    char buffer[] = "Hello testing";

    pFile = fopen("test.txt", "w");

    if (NULL == pFile) {
        puts("open failure");
        return 1;
    } else {
        fwrite(buffer, 1, sizeof(buffer), pFile);
    }

    fclose(pFile);

    truncate("test.txt", 20);

    fd = open("test.txt", O_CREAT | O_WRONLY | O_TRUNC, 0666);

    ftruncate(fd, 0);

    close(fd);

    return 0;
}
