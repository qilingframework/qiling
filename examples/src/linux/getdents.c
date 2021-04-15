#include "stdio.h"
#include <sys/types.h>
#include <dirent.h>
void main()
{
    //int aa = O_RDONLY|O_NDELAY|O_DIRECTORY|O_LARGEFILE|O_CLOEXEC;
    DIR *dirptr = NULL;
    struct dirent *ptr;
    dirptr = opendir("/");

    while ((ptr = readdir(dirptr)) != NULL)
    {
        printf("%s\n", ptr->d_name);
    }

    if (dirptr == NULL)
    {
        printf("Open dir error !\n");
    }
    else
        printf("Open Success!\n");
    close(dirptr);
}