CC := gcc
CFLAGS := -Wall -Wextra -O2 -D_GNU_SOURCE
LDLIBS := -lpthread -lssl -lcrypto

.PHONY: all clean

all: server

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f server *.o
