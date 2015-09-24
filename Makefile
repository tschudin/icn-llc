# Makefile

BINARIES= llc-cli llc-peer llc-test-client llc-test-client2

all: ${BINARIES}

llc-cli: Makefile llc-cli.c 
	${CC} -o $@ -lreadline $@.c

llc-peer: Makefile llc-peer.c
	gcc -o $@ -lwolfssl $@.c

llc-test-client: Makefile llc-test-client.c
	gcc -o $@ $@.c

llc-test-client2: Makefile llc-test-client2.c
	gcc -o $@ $@.c

clean:
	rm -rf ${BINARIES} *~
