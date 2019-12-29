#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(int argc, const char **argv) {
    execve("bin/x8664_hello_static",NULL,NULL);
    return -1;
}
