# Makefile

BINARIES= llc-cli llc-peer llc-test-client llc-test-client2 llc-dtls-test llc-dtls-client-test

all: ${BINARIES}

llc-cli: Makefile llc-cli.c
	${CC} -o $@ -lreadline $@.c

llc-peer: Makefile llc-peer.c
	gcc -o $@ $@.c -lwolfssl

llc-dtls-test: Makefile llc-dtls-test.c
	gcc -o $@ $@.c -lwolfssl

llc-dtls-client-test: Makefile llc-dtls-client-test.c
	gcc -o $@ $@.c -lwolfssl

llc-test-client: Makefile llc-test-client.c
	gcc -o $@ $@.c

llc-test-client2: Makefile llc-test-client2.c
	gcc -o $@ $@.c

clean:
	rm -rf ${BINARIES} *~
