# Makefile

all: llc-cli llc-peer

llc-cli: Makefile llc-cli.c 
	${CC} -o $@ -lreadline $@.c

llc-peer: Makefile llc-peer.c
	gcc -o $@ -lwolfssl $@.c

clean:
	rm -rf llc-cli *~
