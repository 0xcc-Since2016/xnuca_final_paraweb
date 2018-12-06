all: server

clean:
	@rm -rf *.o
	@rm -rf server

server: main.o httpd.o
	gcc -o server $^ `mysql_config --cflags --libs`

main.o: main.c httpd.h
	gcc -c -o main.o main.c `mysql_config --cflags --libs`

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c `mysql_config --cflags --libs`

