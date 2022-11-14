CC=gcc
# idk, really
FLAGS=-B -B

all:
	$(CC) $(FLAGS) -o dns_receiver receiver/*.c include/*.c
	$(CC) $(FLAGS) -o dns_sender sender/*.c include/*.c

.PHONY: subdirs sender receiver include
receiver:
	$(CC) $(FLAGS) -o dns_receiver receiver/*.c include/*.c

.PHONY: subdirs sender receiver include
sender:
	$(CC) $(FLAGS) -o dns_sender sender/*.c include/*.c

archive:
	tar -cvf xtikho00.tar include sender receiver manual.pdf README Makefile test
