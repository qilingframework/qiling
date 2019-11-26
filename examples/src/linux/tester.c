#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {
    int i=0;
    int d;
    float f;
    long int l;
    FILE *file = NULL;
    printf("\ncmdline args count=%d", argc);

    /* First argument is executable name only */
    printf("\nexe name=%s", argv[0]);

    for (i=1; i< argc; i++) {
            printf("\narg%d=%s", i, argv[i]);
             }

    /* Conversion string into int */
    d = atoi(argv[1]);
    printf("\nargv[1] in intger=%d",d);

    /* Conversion string into float */
    f = atof(argv[1]);
    printf("\nargv[1] in float=%f",f);

    /* Conversion string into long int */
    l = strtol(argv[2], NULL, 0);
    printf("\nargv[2] in long int=%ld",l);

    /*Open file whose path is passed as an argument */
    file = fopen( argv[3], "r" );

    /* fopen returns NULL pointer on failure */
    if ( file == NULL) {
            printf("\nCould not open file");
              }
    else {
            printf("\nFile (%s) opened", argv[3]);
                /* Closing file */
                fclose(file);
                  }

    printf("\n");
    return 0;
}
