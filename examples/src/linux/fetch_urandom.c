#include <stdio.h>

int main(void) {
    FILE *fp;
    int randno; 

    if ((fp = fopen("/dev/urandom", "r")) == NULL) {
	    fprintf(stderr, "Error! Could not open /dev/urandom for read\n");
    	return -1;
    }

    randno = fgetc(fp);
    printf("randno: %d\n", randno);
    fclose(fp);

    return 0;
}

