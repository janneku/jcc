OBJS = main.o
CC = gcc
CFLAGS = -W -Wall -O2 -g

jcc: $(OBJS)
	$(CC) -o $@ $(OBJS)
