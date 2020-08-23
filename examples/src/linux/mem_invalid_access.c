#include<stdio.h>

void test_write(){
    char * ptr = 0xaabbccdd;
    *ptr = 'W';
    printf("%c", *ptr);
}

void test_read(){
    char * ptr = 0xbbccddee;
    printf("%c", *ptr);
}

int main(){
    test_write();
    test_read();
    return 0;
}