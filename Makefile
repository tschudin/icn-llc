# Makefile

all: llc-cli

llc-cli: llc-cli.c
	${CC} -o $@ $<

clean:
	rm -rf llc-cli *~
