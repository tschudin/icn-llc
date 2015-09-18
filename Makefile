# Makefile

all: llc-cli

llc-cli: llc-cli.c
	${CC} -o $@ -lreadline $<

clean:
	rm -rf llc-cli *~
