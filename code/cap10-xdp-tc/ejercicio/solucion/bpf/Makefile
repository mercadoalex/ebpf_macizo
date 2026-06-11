CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

.PHONY: all clean

all: xdp_firewall.bpf.o

xdp_firewall.bpf.o: xdp_firewall.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
