CC=gcc
CFLAGS=

all: reil_translator

reil_translator: libdasm.o reil_translator.o
	$(CC) $(CFLAGS) -c libdasm.c
	$(CC) $(CFLAGS) -c  reil_translator.c
	$(CC) $(CFLAGS) reil_translator.o libdasm.o -o reil_translator

clean:
	rm -f *.o
