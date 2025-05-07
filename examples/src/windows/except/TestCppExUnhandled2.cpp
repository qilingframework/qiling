#include <iostream>
#include <cstdio>

int main()
{
    /*
     * For this program, all subtests successful will print:
     * - 1 'GOOD'
     * - 0 'BAD'
     * 
     * It is expected that the program terminates abnormally
     * with status code 0xC0000409 (stack buffer overrun/security
     * check failure)
     */

    printf("Before throw (GOOD)\n");

    throw (unsigned int)5;

    printf("After throw (BAD)\n");
}
