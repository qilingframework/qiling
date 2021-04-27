#include <stdio.h>
#include <stdlib.h>

void atexit_func(void)
{
	printf("atexit\n");
}

int main(int argc, char** argv, char** envp)
{
	int i = 0;

	atexit(atexit_func);

	printf("Hello, Qiling! argc=%d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("argv[%d] = '%s'\n", i, argv[i]);
	}

	for (i = 0; envp[i] != NULL; i++) {
        	printf("env[%d] = '%s'\n", i, envp[i]);
	}
	return 0;
}
