all: server arm_server

clean:
	@rm -rf *.o
	@rm -rf server
	@rm -rf arm_server

server: main.o httpd.o
	gcc -o server $^
	@rm -rf *.o

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

arm_server: arm_main.o arm_httpd.o
	arm-linux-gnueabi-gcc-10 -o arm_server $^
	@rm -rf *.o

arm_main.o: main.c httpd.h
	arm-linux-gnueabi-gcc-10 -c -o arm_main.o main.c

arm_httpd.o: httpd.c httpd.h
	arm-linux-gnueabi-gcc-10 -c -o arm_httpd.o httpd.c