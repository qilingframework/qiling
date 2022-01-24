// gcc -static ~/qiling/examples/src/linux/path_traverse.c -g -O0 -o ~/qiling/examples/rootfs/x8664_linux/bin/path_traverse_static
// https://www.kalmarunionen.dk/writeups/2022/rwctf/qlaas/
#include <fcntl.h>
#include <unistd.h>

int main(){
	char buf[4096];
	int fd = openat(1, "/etc/passwd", O_RDONLY);
	ssize_t len = read(fd, buf, sizeof(buf));
	write(1, buf, len);

	fd = openat(1, "/etc/passwd_link", O_RDONLY);
	len = read(fd, buf, sizeof(buf));
	write(1, buf, len);
}
