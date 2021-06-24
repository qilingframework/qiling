#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Program that will crash easily.
#define SIZE (10)

int fun(int i) {
    char *buf = malloc(SIZE);
    char buf2[SIZE];
    while (*buf = getc(stdin) == 'A') {
        buf[i++] = *buf;
    }
    strncpy(buf2, buf, i);
    printf(buf2);
    return 0;
}

int main(int argc, char **argv) {
    return fun(argc);
}
