CC = gcc

SRC=daemon/*.c

all: junq-daemon

run: junq-daemon
	./junq-daemon

junq-daemon: $(SRC)
	$(CC) $(SRC) -o junq-daemon -DNDEBUG -O2 -s
