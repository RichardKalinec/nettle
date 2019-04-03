TARGET=measureBlindedRSA
CPPFLAGS=
CFLAGS=-O0 -g -Wall -W -Wmissing-prototypes -Wmissing-declarations \
       -Wstrict-prototypes -Wpointer-arith -Wbad-function-cast \
       -Wnested-externs  -D_GNU_SOURCE \
       -DCLOCK_PROCESS_CPUTIME_ID=CLOCK_MONOTONIC_RAW
LDLIBS=-lhogweed -lnettle -lgmp
LDEXTRAFLAGS=-rdynamic
CC=gcc

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ core $(TARGET)

.PHONY: clean
