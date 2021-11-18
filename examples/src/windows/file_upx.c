#include <stdio.h>
int main()
{
    FILE *f;
    const char *filename = "test.bin";
    unsigned char buf[5] = {1, 2, 3, 4, 5};
    f = fopen(filename, "wb");
    fwrite(buf, 1, 5, f);
    fclose(f);
    f = fopen(filename, "rb");
    fread(buf, 1, 5, f);
    fclose(f);
    remove(filename);
    return 0;
}
