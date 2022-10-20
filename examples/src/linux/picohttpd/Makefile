all: x64_server arm_server

clean:
	@rm -rf *.o
	@rm -rf x64_server
	@rm -rf arm_server

x64_server: main.o httpd.o
	gcc -o x64_server $^
	@rm -rf *.o

x64_main.o: main.c httpd.h
	gcc -c -o x64_main.o main.c

x64_httpd.o: httpd.c httpd.h
	gcc -c -o x64_httpd.o httpd.c

arm_server: arm_main.o arm_httpd.o
	arm-linux-gnueabi-gcc-10 -o arm_server $^
	@rm -rf *.o

arm_main.o: main.c httpd.h
	arm-linux-gnueabi-gcc-10 -c -o arm_main.o main.c

arm_httpd.o: httpd.c httpd.h
	arm-linux-gnueabi-gcc-10 -c -o arm_httpd.o httpd.c