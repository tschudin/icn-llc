# Makefile

BINARIES= llc-peer llc-test-client llc-test-client2 llc-dtls-client-test
LIBS=-I /usr/local/include -L /usr/local/lib

all: ${BINARIES}

# llc-cli: Makefile llc-cli.c
#	${CC} -o $@ -lreadline $@.c

llc-peer: Makefile llc-peer.c llc-cmd.c
	gcc -o $@ $@.c -g -lreadline -lwolfssl ${LIBS}

llc-dtls-client-test: Makefile llc-dtls-client-test.c
	gcc -o $@ $@.c -lwolfssl ${LIBS}

llc-test-client: Makefile llc-test-client.c
	gcc -o $@ $@.c

llc-test-client2: Makefile llc-test-client2.c
	gcc -o $@ $@.c

clean:
	rm -rf ${BINARIES} *~
