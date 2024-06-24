CC = gcc

SRC=daemon/*.c

CFLAGS= -static

all: junq-daemon

run: junq-daemon
	./junq-daemon

junq-daemon: $(SRC)
	$(CC) $(SRC) $(CFLAGS) -o junq-daemon -DNDEBUG -O2 -s