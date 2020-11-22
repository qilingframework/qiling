#include <stdio.h>
#include <sys/mman.h>
#include <memory.h>
#include <errno.h>

int main(int argc, const char **argv) {
	char shellcode[] = 
		"\x48\xC7\xC0\x3C\x00\x00\x00" // mov rax, 0x3c (exit)
		"\x48\xC7\xC7\x2A\x00\x00\x00" // mov rdi, 42
		"\x0F\x05";                    // syscall
	char* buf = (char*) mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,0,0);
	memcpy(buf, shellcode, sizeof(shellcode));
	mprotect(buf, 0x1000, PROT_EXEC);
	(*(void(*)())buf)();
    return 0;
}
