#include <windows.h>
#include <cstdio>

void test1() {
    __try {
        printf("Inside __try block. (GOOD)\n");

        RaiseException(
            0xE0000001,
            0,
            0,
            nullptr
        );

        printf("After RaiseException. (BAD)\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("In __except block. (GOOD)\n");

        unsigned long excepCode = GetExceptionCode();

        printf("Exception code=0x%x\n", excepCode);

        if (excepCode == 0xE0000001) {
            printf("Exception code IS same, GOOD\n");
        }
        else {
            printf("Exception code DOES NOT MATCH, BAD\n");
        }
    }

    printf("After __except block. (GOOD)\n");
}

int main() {
    /*
     * For this program, all subtests successful will print:
     * - 4 'GOOD'
     * - 0 'BAD'
     */

    test1();

    return 0;
}
