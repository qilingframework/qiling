#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_cwd(){
	char buf[4096];
	getcwd(buf, 4096);
	printf("%s\n", buf);
}

int main(){
	print_cwd();
	// Firstly, we chdir by relative path.
	chdir("lib");
	print_cwd();
	// Then, by absolute path.
	chdir("/bin");
	print_cwd();
	// Last, test rootfs.
	chdir("/");
	print_cwd();
	return 0;
}
