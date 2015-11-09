# Makefile

BINARIES= llc-peer llc-test-client llc-test-client2 llc-cmd
LIBS=-I /usr/local/include -L /usr/local/lib

all: ${BINARIES}

llc-cmd: Makefile llc-cmd.c
	${CC} -o $@ -DBUILD -lreadline $@.c

llc-peer: Makefile llc-peer.c llc-cmd.c
	gcc -o $@ $@.c -g -lreadline -lwolfssl ${LIBS}

llc-test-client: Makefile llc-test-client.c
	gcc -o $@ $@.c

llc-test-client2: Makefile llc-test-client2.c
	gcc -o $@ $@.c

clean:
	rm -rf ${BINARIES} *~
