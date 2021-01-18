#include <Windows.h>
#include <stdio.h>

// These definitions are wrong, but tcc does not properly read them otherwise!
extern char** _acmdln;
extern wchar_t** _wcmdln;

extern
char **__p__acmdln(void);
extern
wchar_t **__p__wcmdln(void);

int main(int argc, char* argv[])
{
    int i;
    for (i = 0; i < argc; ++i)
    {
        printf("arg[%i]: <%s>\n", i, argv[i]);
    }

    printf("_acmdln: <%s>\n", *_acmdln);
    wprintf(L"_wcmdln: <%s>\n", *_wcmdln);

#if !defined(_WIN64)
    // Not present on x64 msvcrt.dll
    printf("__p__acmdln: <%s>\n", *__p__acmdln());
    wprintf(L"__p__wcmdln: <%s>\n", *__p__wcmdln());
#endif

    printf("GetCommandLineA: <%s>\n", GetCommandLineA());
    wprintf(L"GetCommandLineW: <%s>\n", GetCommandLineW());

    return 0;
}
