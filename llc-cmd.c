/* 
 * @f llc-cmd.c
 * @b ICN-LLC - command execution (ASCII console for the time being)
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
        struct sexpr *list;
        int intval;
        char *strval;
    } s;
};

#define SEXPR_LST 1
#define SEXPR_INT 2
#define SEXPR_STR 3

struct nsnode;
typedef int (*ns_callback)(struct nsnode*, struct sexpr *old);

struct nsnode { // namespace node
    struct nsnode *parent, *children;
    struct nsnode *next, *prev;
    char *relname;
    struct sexpr *val;
    ns_callback set_cb;
};

struct nsnode *nsroot;
char namebuf[512];

char* ring_expand(char *path);

// ----------------------------------------------------------------------

#define RPC_OK   0
#define RPC_FAIL 1

#define RETURN_RESULT(C,S) do { \
        char *CP = S ? S : "";                     \
        if (C == RPC_OK) printf("OK (%s)\n", CP);  \
        else printf("FAIL (%s)\n", CP);            \
    } while (0)

// ----------------------------------------------------------------------
// symbolic expression handling

// parse a str containing a symbolic expression, return a new sexpr struct
struct sexpr*
sexpr_parse(char **s)
{
    struct sexpr *e;

    while (isspace(**s))
        *s += 1;
    if (**s == '\"') {
        char *cp = *s;
        for (*s += 1; **s && **s != '\"'; *s += 1);
        e = calloc(1, sizeof(*e));
        e->type = SEXPR_STR;
        e->s.strval = calloc(1, *s - cp);
        cp++;
        memcpy(e->s.strval, cp, *s - cp);
        if (**s == '\"')
            *s += 1;
        e->s.strval = ring_expand(e->s.strval);
        return e;
    }
    if (isdigit(**s)) {
        int val = **s - '0';
        *s += 1;
        while (isdigit(**s)) {
            val = 10*val + **s - '0';
            *s += 1;
        }
        e = calloc(1, sizeof(*e));
        e->type = SEXPR_INT;
        e->s.intval = val;
        return e;
    }
    if (**s == '(') {
        struct sexpr *lst = calloc(1, sizeof(*lst)), *tail;

        *s += 1;
        lst->type = SEXPR_LST;
        for (;;) {
            e = sexpr_parse(s);
            if (!e)
                break;
            if (!lst->s.list)
                lst->s.list = e;
            else
                tail->next = e;
            tail = e;
        }
        while (isspace(**s))
            *s += 1;
        if (**s != ')')
            return NULL;
        *s += 1;
        return lst;
    }
    return NULL;
}

// parse a str containing a symbolic expression, return a new sexpr struct
struct sexpr*
sexpr_fromStr(char *s)
{
    char *cp = s;

    return sexpr_parse(&cp);
}

// write a sexpr struct into a string (malloced)
int
sexpr_toStr(char *buf, int buflen, struct sexpr *e)
{
    char *start = buf;

    if (!e)
        return 0;
    // we should honor buflen ...
    switch (e->type) {
    case SEXPR_INT:
        buf += sprintf(buf, "%d", e->s.intval);
        break;
    case SEXPR_STR:
        buf += sprintf(buf, "\"%s\"", e->s.strval);
        break;
    case SEXPR_LST:
        buf += sprintf(buf, "(");
        for (e = e->s.list; e; e = e->next) {
            buf += sexpr_toStr(buf, buflen, e);
            if (e->next)
                buf += sprintf(buf, " ");
        }
        buf += sprintf(buf, ")");
        break;
    default:
        return 0;
    }
    return buf - start;
}

// release (recursively) a sexpr struct
void
sexpr_free(struct sexpr *e)
{
    if (!e)
        return;
    if (e->type == SEXPR_STR && e->s.strval)
        free(e->s.strval);
    else if (e->type == SEXPR_LST) {
        while (e->s.list) {
            struct sexpr *e2 = e->s.list->next;
            sexpr_free(e->s.list);
            e->s.list = e2;
        }
    }
    free(e);
}

// ----------------------------------------------------------------------
// namespace mangement

// add a new child node to a namespace node
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

// assign a new value to a namespace node, trigger the set callback
void
ns_setExpr(struct nsnode *n, struct sexpr *e)
{
    struct sexpr *old = n->val;
    
    n->val = e;
    if (n->set_cb)
        (n->set_cb)(n, old);
    sexpr_free(old);
}

// remove a namespace node, trigger the destroy callback
void
ns_rmNode(struct nsnode *n)
{
}

// walk the namespace as requested by the expanded path, return the node
struct nsnode*
ns_find(char *path)
{
    char *p2, *s;
    struct nsnode *n = nsroot->children, *start;

    if (!path)
        return NULL;
    p2 = ring_expand(strdup(path));
    s = strtok(p2, "/");

    start = n;
    do {
check:
        if (!strcmp(s, n->relname)) {
            s = strtok(NULL, "/");
            if (!s) {
                free(p2);
                return n;
            }
            n = n->children;
            if (!n) {
                free(p2);
                return NULL;
            }
            start = n;
            goto check;
        }
        n = n->next;
    } while (n != start);
    free(p2);
    return NULL;
}

// extend the namespace as requested by the expanded path, return the node
struct nsnode*
ns_mkNode(char *path)
{
    char *p2, *s;
    struct nsnode *parent = nsroot, *n = nsroot->children, *start;

    if (!path)
        return NULL;
    p2 = ring_expand(strdup(path));
    s = strtok(p2, "/");

    start = n;
    do {
check:
        if (!strcmp(s, n->relname)) {
            s = strtok(NULL, "/");
            if (!s) { // node already exists, return it
                free(p2);
                return n;
            }
            parent = n;
            n = n->children;
            if (!n)
                break;
            start = n;
            goto check;
        }
        n = n->next;
    } while (n != start);
    // *parent is the last node we could walk to, create new children
    while (s) {
        parent = ns_addChild(parent, s);
        s = strtok(NULL, "/");
    }
    free(p2);
    return parent;
}

// return the node's namespace path
char*
ns_node2path(char *buf, int len, struct nsnode *n)
{
    char *cp;

    len--;
    cp =  buf + len;
    *cp = '\0';
    
    while (n) {
        if (n->relname) {
            int i = strlen(n->relname);
            if (len >= i) {
                cp -= i;
                len -= i;
                memcpy(cp, n->relname, i);
            }
        }
        if (n->parent && len > 0) {
            cp--;
            len--;
            *cp = '/';
        }
        n = n->parent;
    }
    return buf + len;
}

// ----------------------------------------------------------------------
// circular buffer for return values, index by command line number

#define RINGSIZE 50
char* ringbuf[RINGSIZE];
int ringndx, ringoffs;

// add an entry to the ring buffer, eliminate oldest overflow item
void
ring_addValue(int linecnt, char *val)
{
    if (ringbuf[ringndx])
        free(ringbuf[ringndx]);
    if (val)
        ringbuf[ringndx] = strdup(val);
    else
        ringbuf[ringndx] = NULL;
    ringoffs = linecnt;
    ringndx = (ringndx + 1) % RINGSIZE;
}

// retrieve value by line number
char*
ring_getValueByLN(int linecnt)
{
    if (linecnt > ringoffs || linecnt <= (ringoffs - RINGSIZE))
        return NULL;
    return ringbuf[(ringndx - 1 + RINGSIZE - ringoffs + linecnt) % RINGSIZE];
}

// takes a malloced str, expands any $xx inside it, returns new buffer
char*
ring_expand(char *str)
{
    int len, pos, pos$, ndx;

    for (len = strlen(str)+1, pos = 0, ndx = -1;; pos++) {
        if (str[pos] == '$') {
            pos$ = pos;
            ndx = 0;
        } else if (ndx >= 0) {
            if (isdigit(str[pos]))
                ndx = 10 * ndx + str[pos] - '0';
            else {
                char *cp = ring_getValueByLN(ndx);
                if (cp) {
                    int len2 = strlen(cp), len3;
                    len3 = len + len2 - (pos - pos$);
                    str = realloc(str, len3);
                    memmove(str + pos$ + len2,
                            str + pos, (len - 1 - pos));
                    memcpy(str + pos$, cp, len2);
                    pos = pos$ + len2;
                }
                ndx = -1;
            }
        }
        if (!str[pos])
            break;
    }
    
    return str;
}

// ----------------------------------------------------------------------

// demo namespace
struct nsnode*
init(void)
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

// ----------------------------------------------------------------------
// CLI

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
            "  mk pipe LINK LOCALDEV REMOTESRVC\n"
            "  mk srvc SRVCNAME LOCALDEV\n"
            "  get NAME\n"
            "  set NAME VALUE\n"
            "  rm NAME\n"
            "  rpc LINK COMMAND\n\n"
            "  dump\n"
            "  peek OFFS LEN\n"
            "  help    produces this output\n"
            "  list    produces variable tree\n"
            "  quit    quits\n"
            "  var     lists the stored return values\n"
        );
}

char*
cmd_mk(char *line)
{
    char *kind = strtok(NULL, " \t\n"), *cp;

    if (!strcmp(kind, "node")) {
        char *name = strtok(NULL, " \t\n");
        struct nsnode *n = ns_mkNode(name);
        if (n) {
            cp = ns_node2path(namebuf, sizeof(namebuf), n);
            RETURN_RESULT(RPC_OK, cp);
            return cp;
        }
        RETURN_RESULT(RPC_FAIL, "?");
        return NULL;
    }
    
    
    RETURN_RESULT(RPC_FAIL, "mk not implemented");
    return NULL;
}

char*
cmd_get(char *line)
{
    char *name = strtok(NULL, " \t\n");
    struct nsnode *n = ns_find(name);

    if (!n) {
        RETURN_RESULT(RPC_FAIL, "no such name");
    } else if (!n->val) {
        RETURN_RESULT(RPC_FAIL, "no value for this name");
    } else {
        if (sexpr_toStr(namebuf, sizeof(namebuf), n->val)) {
            RETURN_RESULT(RPC_OK, namebuf);
            return namebuf;
        }
        RETURN_RESULT(RPC_OK, NULL);
    }
    return NULL;
}

char*
cmd_set(char *line)
{
    char *name = strtok(NULL, " \t\n");
    char *expr = strtok(NULL, "\n");
    struct sexpr *e = expr ? sexpr_fromStr(expr) : NULL;
    struct nsnode *n = ns_find(name);

    if (!n) {
        RETURN_RESULT(RPC_FAIL, "no such name");
        sexpr_free(e);
    } else if (!e) {
        RETURN_RESULT(RPC_FAIL, "invalid expression");
    } else {
        ns_setExpr(n, e);
        RETURN_RESULT(RPC_OK, NULL);
        return ns_node2path(namebuf, sizeof(namebuf), n);
    }
    return NULL;
}

void
cmd_rm(char *line)
{
    RETURN_RESULT(RPC_FAIL, "rm not implemented");
}

void
cmd_rpc(char *line)
{
    RETURN_RESULT(RPC_FAIL, "rpc not implemented");
}

void
cmd_list(int lev, struct nsnode *n)
{
    char buf[1024];
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
            sexpr_toStr(buf, sizeof(buf), n->val);
            printf("=%s\n", buf);
        } else
            printf("\n");
        n = n->next;
    } while (n != start);
}

void
cmd_dump(char *line)
{
    RETURN_RESULT(RPC_FAIL, "dump not implemented");
}

void
cmd_peek(char *line)
{
    RETURN_RESULT(RPC_FAIL, "peek not implemented");
}

static int linecnt;

int
llc_execute(char *line)
{
    char *verb, *val;
    
    if (!line)
        return 0;
    
    for (verb = line; isspace(*verb); verb++);
    if (!*verb || *verb == '#') // empty line or comment
        return 0;

    add_history(line);

    verb = strtok(line, " \t\n");
    val = NULL;
    if (!strcmp(verb, "mk"))
        val = cmd_mk(line);
    else if (!strcmp(verb, "get"))
        val = cmd_get(line);
    else if (!strcmp(verb, "set"))
        val = cmd_set(line);
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
    else if (!strcmp(verb, "var")) {
        int i;
        for (i = -10; i < 0; i++) {
            char *s = ring_getValueByLN(linecnt + i);
            printf(" $%d is %s\n", linecnt + i, s);
        }
    } else if (!strcmp(verb, "quit"))
        return -1;
    else {
        fprintf(stderr, "unknown verb \"%s\", "
                "see full list with \"help\"\n", verb);
    }

    if (val) {
        ring_addValue(linecnt, val);
        linecnt++;
    }
    return 0;
}

#ifdef XXX
int
main(int argc, char **argv)
{
    int linecnt = 0;

    printf("ICN-LLC command line interface\n\n");

    using_history();
    nsroot = init();

    for (;;) {
        char *verb, *line, prompt[20], *val;
        sprintf(prompt, "llc %d> ", linecnt);
        line = readline(prompt);

        if (!line)
            break;
    }

    printf("\n* llc-cli ends here.\n");
    return 0;
}
#endif

// eof
