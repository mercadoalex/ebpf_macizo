CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

SOURCES := $(wildcard *.bpf.c)
OBJECTS := $(SOURCES:.bpf.c=.bpf.o)

.PHONY: all clean

all: $(OBJECTS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
