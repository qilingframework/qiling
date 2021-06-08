#include <string.h>

#include "patch_test.so.h"

int main(int argc, const char **argv)
{
    const char* p = patch_test_value;

    if (strcmp(p, "qiling"))
    {
        /* crash with an illegal instruction */
        __builtin_trap();
    }

    return 0;
}

// run:
//   LD_LIBRARY_PATH=. ./patch_test.bin