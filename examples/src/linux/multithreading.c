#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

// thread 1
void thread_1(void) {
    int i = 0;
    for(i = 0; i <= 6; i++) {
        printf("This is a pthread_1.\n");
        if(i == 2) {
            pthread_exit(3);
            return 3;
        }
        sleep(1);
    }
}

// thread 2
void thread_2(void) {
    int i;
    for(i = 0; i < 3; i++) {
        printf("This is a pthread_2.\n");
    }
    pthread_exit(2);
    return 2;
}

int main(void) {
    pthread_t id_1, id_2;
    int ret;

    /*Create pthread 1*/
    ret=pthread_create(&id_1, NULL, (void  *) thread_1, NULL);
    if(ret != 0) {
        printf("Create pthread error!\n");
        return -1;
    }

    /*Create pthread 2*/
    ret=pthread_create(&id_2, NULL, (void  *) thread_2, NULL);
    if(ret != 0) {
        printf("Create pthread error!\n");
        return -1;
    }

    /*wait thread ending*/
    pthread_join(id_1, &ret);
    printf("thread 1 ret val is : %d\n", ret);
    pthread_join(id_2, &ret);
    printf("thread 2 ret val is : %d\n", ret);
    return 0;
}