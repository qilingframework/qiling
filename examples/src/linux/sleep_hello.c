#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void func_hello()
{
    printf("Hello, World!\n");

    return;
}

int main(int argc, const char **argv)
{
    printf("sleep 3600 seconds...\n");
    sleep(3600);
    printf("wake up.\n");

    func_hello();

    return 0;
}
