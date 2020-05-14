#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "patch_test.so.h"

int main(int argc, const char **argv)
{
    int ret;
    const char *p;

    p = patch_test_value;

    ret = strcmp(p, "qiling");
    if (ret) {
        /* crash */
        memcpy(NULL, p, 4);
    }

    return 0;
}
