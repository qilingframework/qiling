// Modified from https://github.com/qilingframework/qiling/issues/484
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void read_and_print(){
	char data[4096];
	FILE* f = fopen("/absolutepath_test.txt", "r");
	int count = fread(data, 1, 4096, f);
	fclose(f);
	data[count] = 0;
	printf("%s\n", data);
}

int main() {
	read_and_print();
	chdir("/lib");
	read_and_print();
	return 0;
}
