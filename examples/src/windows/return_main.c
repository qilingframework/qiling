/*
Build with tcc (https://download.savannah.gnu.org/releases/tinycc/)
Renamed 64 bit tcc to 'tcc64' for convenience:

tcc return_main.c -nostdlib -o return_main32.exe
tcc64 return_main.c -nostdlib -o return_main64.exe
*/

int _start()
{
    return 0;
}
