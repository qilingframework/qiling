#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *args[] = {"child", "arg1", "arg2", NULL};
char *env[] = {"QL_TEST=TEST_QUERY", NULL};

int main(int argc, const char **argv) {
    execve("bin/x8664_hello_static", args, env);
    return -1;
}
