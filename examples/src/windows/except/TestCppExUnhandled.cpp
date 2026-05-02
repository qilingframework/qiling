#include <windows.h>
#include <cstdio>

LONG WINAPI CustomExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo) {
    printf("Inside exception filter (GOOD)\n");
    DWORD exceptionCode = (DWORD)ExceptionInfo->ExceptionRecord->ExceptionCode;
    printf("Exception Code: 0x%X\n", exceptionCode);

    if (exceptionCode == 0xE06D7363) { // code for C++ exception
        printf("Exception code DOES match, GOOD\n");
    }
    else {
        printf("Exception code DOES NOT match, BAD\n");
    }

    printf("Exception Address: 0x%llx\n", (ULONGLONG)ExceptionInfo->ExceptionRecord->ExceptionAddress);

    printf("After printing exception: (GOOD)\n");
    
    return EXCEPTION_EXECUTE_HANDLER;
}

int main() {
    /*
     * For this program, all subtests successful will print:
     * - 3 'GOOD'
     * - 0 'BAD'
     * 
     * It is expected that the program terminates abnormally
     * with status code 0xE06D7363 (C++ exception)
     */

    // Set the custom top-level exception filter
    SetUnhandledExceptionFilter(CustomExceptionFilter);

    // Throw an unhandled exception.
    // It should be caught by our filter.
    throw (unsigned int)5;

    // We should never reach this point, because the exception
    // dispatcher should terminate the program after our unhandled
    // exception filter is called.
    printf("After exception filter (BAD)\n");

    return 0;
}