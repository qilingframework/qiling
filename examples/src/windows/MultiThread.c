#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>


DWORD WINAPI ThreadFun(LPVOID pM)
{
    char *test = (char *)pM;
    printf(test);
    printf("child tread: thread id is %d\n", GetCurrentThreadId());
    return 0;
}

int main()
{
    printf("main thread\n");
    char test[] = "child thread\n";
    DWORD threadId = 0;
    HANDLE handle = CreateThread(NULL, 0, ThreadFun, (LPVOID)test, 0, &threadId);
    printf("main thread: child thread id is %d\n", threadId);
    WaitForSingleObject(handle, INFINITE);
    CloseHandle(handle);
    return 0;
}