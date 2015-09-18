/* 
 * @f llc-cli.c
 * @b ICN-LLC - command line interface
 *
 * Copyright (C) 2015, Christian Tschudin, University of Basel
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File history:
 * 2015-09-17 created
 */


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>
#include <readline/history.h>

struct sexpr { // atom or list
    char type;
    struct sexpr *next;
    union {
	int intval;
	char *strval;
	struct sexpr *list;
    } s;
};

#define SEXPR_LST 1
#define SEXPR_INT 2
#define SEXPR_STR 3


struct nsnode { // namespace node
    struct nsnode *parent, *children;
    struct nsnode *next, *prev;
    char *relname;
    struct sexpr *val;
};

struct nsnode *nsroot;

// ----------------------------------------------------------------------

struct sexpr*
sexpr_fromStr(char *s)
{
    char *cp = s;
    struct sexpr *e = calloc(1, sizeof(struct sexpr));

    while (isspace(*cp))
	cp++;
    if (isdigit(*cp)) {
	e->type = SEXPR_INT;
	e->s.intval = atoi(cp);
	return e;
    }
    if (*cp == '\"') {
	cp++;
	for (s = cp; s && *s != '\"'; s++);
	e->type = SEXPR_STR;
	e->s.strval = calloc(1, s - cp + 1);
	memcpy(e->s.strval, cp, s - cp);
	return e;
    }
    free(e);
    return NULL;
}

char*
sexpr_toStr(struct sexpr *e)
{
    static char buf[1024];

    if (!e)
	return NULL;
    switch (e->type) {
    case SEXPR_INT:
	sprintf(buf, "%d", e->s.intval);
	break;
    case SEXPR_STR:
	sprintf(buf, "\"%s\"", e->s.strval);
	break;
    default:
	return NULL;
    }
    return buf;
}

void
sexpr_free(struct sexpr *e)
{
    if (!e)
	return;
    if (e->type == SEXPR_STR && e->s.strval)
	free(e->s.strval);
    // should also check other assignments and remove them
    // if (n->val.type == SEXPR_LST ...
    free(e);
}


struct nsnode*
ns_addChild(struct nsnode *parent, char *name)
{
    struct nsnode *child = calloc(1, sizeof(struct nsnode));
    
    child->parent = parent;
    child->relname = strdup(name);
    if (!parent->children) {
	child->next = child->prev = child;
	parent->children = child;
    } else {
	child->prev = parent->children->prev;
	child->next = parent->children;
	parent->children->prev->next = child;
	parent->children->prev = child;
    }
    return child;
}

void
ns_setExpr(struct nsnode *n, struct sexpr *e)
{
    sexpr_free(n->val);
    n->val = e;
}

void
ns_rmNode(struct nsnode *n)
{
}

struct nsnode*
ns_init(void)
{
    struct nsnode *n = calloc(1, sizeof(struct nsnode)), *n2, *n3;
    struct sexpr *e;

    n->next = n->prev = n;
    
    n2 = ns_addChild(n, "cert");

    n2 = ns_addChild(n, "dev");
    n3 = ns_addChild(n2, "local");
    n3 = ns_addChild(n2, "remote");

    n2 = ns_addChild(n, "info");
    n3 = ns_addChild(n2, "version");
    e = sexpr_fromStr("\"0.01\"");
    ns_setExpr(n3, e);

    n2 = ns_addChild(n, "key");
    n2 = ns_addChild(n, "link");

    return n;
}

struct nsnode*
ns_find(char *path)
{
    char *p2 = strdup(path), *s;
    struct nsnode *n = nsroot->children, *start;

    s = strtok(p2, "/");
    start = n;
    do {
check:
	if (!strcmp(s, n->relname)) {
	    s = strtok(NULL, "/");
	    if (!s)
		return n;
	    n = n->children;
	    if (!n)
		return NULL;
	    start = n;
	    goto check;
	}
	n = n->next;
    } while (n != start);
    return NULL;
}

void
help(FILE *f)
{
    if (!f)
	f = stdout;

    fprintf(f,
	   "Available commands:\n"
	    "  mk cert FILE\n"
	    "  mk dev PARAMS\n"
	    "  mk key FILE\n"
	    "  mk link LOCALDEV REMOTEDEV\n"
	    "  mk pipe LINK LOCALSRVC REMOTESRVC\n"
	    "  mk srvc DEV LOCALSRVC\n"
            "  get NAME\n"
            "  set NAME VALUE\n"
            "  rm NAME\n"
            "  rpc LINK COMMAND\n\n"
	    "  help\n"
	    "  list\n"
            "  dump\n"
            "  peek OFFS LEN\n"
	    "  quit\n"
	);
}

void
cmd_mk(char *line)
{
    fprintf(stderr, "mk not implemented\n");
}

void
cmd_get(char *line)
{
    char *name = strtok(NULL, " \t\n");
    struct nsnode *n = ns_find(name);

    if (!n)
	fprintf(stderr, "## no such name\n");
    else if (!n->val)
	fprintf(stderr, "## no value for this name\n");
    else
	printf("%s\n", sexpr_toStr(n->val));
}

void
cmd_set(char *line)
{
    char *name = strtok(NULL, " \t\n");
    char *expr = strtok(NULL, "\n");
    struct sexpr *e = sexpr_fromStr(expr);
    struct nsnode *n = ns_find(name);

    if (!n)
	fprintf(stderr, "## no such name\n");
    else if (!e)
	fprintf(stderr, "## invalid expression\n");
    else
	ns_setExpr(n, e);
}

void
cmd_rm(char *line)
{
    fprintf(stderr, "rm not implemented\n");
}

void
cmd_rpc(char *line)
{
    fprintf(stderr, "rpc not implemented\n");
}

void
cmd_list(int lev, struct nsnode *n)
{
    struct nsnode *start = n;
    int i;

    do {
	for (i = 0; i < lev; i++)
	    printf("  ");
	if (n->relname)
	    printf("%s", n->relname);
	if (n->children) {
	    printf("/\n");
	    cmd_list(lev+1, n->children);
	} else if (n->val) {
	    printf("=%s\n", sexpr_toStr(n->val));
	} else
	    printf("\n");
	n = n->next;
    } while (n != start);
}

void
cmd_dump(char *line)
{
    fprintf(stderr, "dump not implemented\n");
}

void
cmd_peek(char *line)
{
    fprintf(stderr, "peek not implemented\n");
}

int
main(int argc, char **argv)
{
    printf("ICN-LLC command line interface\n\n");

    using_history();

    nsroot = ns_init();

    for (;;) {
	char *verb, *line = readline("llc> ");

	if (!line)
	    continue;
	add_history(line);

	verb = strtok(line, " \t\n");
	if (!strcmp(verb, "mk"))
	    cmd_mk(line);
	else if (!strcmp(verb, "get"))
	    cmd_get(line);
	else if (!strcmp(verb, "set"))
	    cmd_set(line);
	else if (!strcmp(verb, "rm"))
	    cmd_rm(line);
	else if (!strcmp(verb, "rpc"))
	    cmd_rpc(line);
	else if (!strcmp(verb, "help"))
	    help(NULL);
	else if (!strcmp(verb, "list"))
	    cmd_list(0, nsroot);
	else if (!strcmp(verb, "dump"))
	    cmd_dump(line);
	else if (!strcmp(verb, "peek"))
	    cmd_peek(line);
	else if (!strcmp(verb, "quit"))
	    break;
	else {
	    fprintf(stderr, "unknown verb \"%s\", "
		    "see full list with \"help\"\n", verb);
	}

	free(line);
    }

    printf("* llc-cli ends here.\n");
    return 0;
}
