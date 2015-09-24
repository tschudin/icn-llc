# Makefile

all: llc-cli llc-peer llc-dtls-test llc-dtls-client-test

llc-cli: Makefile llc-cli.c
	${CC} -o $@ -lreadline $@.c

llc-peer: Makefile llc-peer.c
	gcc -o $@ $@.c -lwolfssl

llc-dtls-test: Makefile llc-dtls-test.c
	gcc -o $@ $@.c -lwolfssl

llc-dtls-client-test: Makefile llc-dtls-client-test.c
	gcc -o $@ $@.c -lwolfssl

clean:
	rm -rf llc-cli llc-peer llc-dtls-test llc-dtls-client-test *~
