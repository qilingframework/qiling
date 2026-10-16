#include <windows.h>

static DWORD g_tlsIndex = TLS_OUT_OF_INDEXES;

static volatile LONG g_hasError = 0;

static DWORD StringLengthA(const char* str) {
    DWORD len = 0;
    while(str && str[len] != '\0') {
        len++;
    }
    return len;
}

static void PrintMessage(const char* message) {
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if(hStdout != INVALID_HANDLE_VALUE && hStdout != NULL && message != NULL) {
        DWORD bytesWritten;
        WriteFile(hStdout, message, (DWORD)StringLengthA(message), &bytesWritten, NULL);
    }
}

DWORD WINAPI ThreadWorker(LPVOID lpParam) {
    int threadId = (int)(UINT_PTR)lpParam;
    void* expectedData = (void*)(UINT_PTR)(threadId + 100);

    void* initialData = TlsGetValue(g_tlsIndex);
    if(GetLastError() != ERROR_SUCCESS || initialData != NULL) {
        char buf[128];
        wsprintfA(buf, "[Thread %d] FAIL Initial TlsGetValue failed or not NULL.\n", threadId);
        PrintMessage(buf);
        InterlockedExchange(&g_hasError, 1);
        return 1;
    }

    if(!TlsSetValue(g_tlsIndex, expectedData)) {
        char buf[128];
        wsprintfA(buf, "[Thread %d] FAIL TlsSetValue failed with error: %lu\n", threadId, GetLastError());
        PrintMessage(buf);
        InterlockedExchange(&g_hasError, 1);
        return 1;
    }

    void* retrievedData = TlsGetValue(g_tlsIndex);
    if(GetLastError() != ERROR_SUCCESS || retrievedData != expectedData) {
        char buf[128];
        wsprintfA(buf, "[Thread %d] FAIL TlsGetValue returned unexpected data.\n", threadId);
        PrintMessage(buf);
        InterlockedExchange(&g_hasError, 1);
        return 1;
    }

    return 0;
}

void EntryPoint(void) {
    int exitCode = 0;

    g_tlsIndex = TlsAlloc();
    if(g_tlsIndex == TLS_OUT_OF_INDEXES) {
        char buf[128];
        wsprintfA(buf, "FAIL TlsAlloc failed with error: %lu\n", GetLastError());
        PrintMessage(buf);
        ExitProcess((UINT)-1);
    }

    #define NUM_THREADS 5
    HANDLE threads[NUM_THREADS];

    for(DWORD i = 0; i < NUM_THREADS; ++i) {
        threads[i] = CreateThread(
            NULL,
            0,
            ThreadWorker,
            (LPVOID)(UINT_PTR)i,
            0,
            NULL
        );

        if(threads[i] == NULL) {
            char buf[128];
            wsprintfA(buf, "FAIL CreateThread failed with error: %lu\n", GetLastError());
            PrintMessage(buf);
            TlsFree(g_tlsIndex);
            ExitProcess((UINT)-1);
        }
    }

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    for(DWORD i = 0; i < NUM_THREADS; ++i) {
        CloseHandle(threads[i]);
    }

    if(!TlsFree(g_tlsIndex)) {
        char buf[128];
        wsprintfA(buf, "FAIL TlsFree failed with error: %lu\n", GetLastError());
        PrintMessage(buf);
        ExitProcess((UINT)-1);
    }

    if(InterlockedCompareExchange(&g_hasError, 0, 0) != 0) {
        PrintMessage("FAIL TLS test completed with errors.\n");
        exitCode = -1;
    } else {
        PrintMessage("SUCCESS All TLS operations succeeded across all threads.\n");
        exitCode = 0;
    }

    ExitProcess((UINT)exitCode);
}