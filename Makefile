CC = gcc
FLAGS = -B

all:
	$(CC) $(FLAGS) -o dns_receiver receiver/*.c
	$(CC) $(FLAGS) -o dns_sender sender/*.c

receiver:
	$(CC) -o dns_receiver reciever/*.c

