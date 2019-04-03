TARGET=ecc-sidechannel
CPPFLAGS=
CFLAGS=-O0 -g -Wall  -D_GNU_SOURCE
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
