all: server

clean:
	@rm -rf *.o
	@rm -rf server

server: main.o httpd.o
	gcc -o server $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c
