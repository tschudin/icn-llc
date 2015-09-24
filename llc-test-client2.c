// llc-test-client2.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

char *icnllc_path = "/tmp/icn-llc.fifo";
char my_path[512];

void
remove_my_path(void)
{
    unlink(my_path);
}

int
main(int argc, char *argv[])
{
    struct sockaddr_un server, me;
    char buf[100];
    int mysock, rc;

    if (argc > 1)
        icnllc_path = argv[1];

    sprintf(my_path, "/tmp/.llc-test-client2-%d.fifo", getpid());
    printf("using a named pipe at %s\n", my_path);
    printf("to contact the ICNLLC server at %s\n", icnllc_path);

    unlink(my_path);
    mysock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mysock < 0) {
        perror("opening datagram socket");
        exit(1);
    }
    me.sun_family = AF_UNIX;
    strcpy(me.sun_path, my_path);
    if (bind(mysock, (struct sockaddr *) &me,
             sizeof(struct sockaddr_un))) {
        perror("binding my path name to datagram socket");
        exit(1);
    }
    atexit(remove_my_path);

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, icnllc_path);

    while( (rc=read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        printf("Sending: %s\n", buf);
        if (sendto(mysock, buf, rc, 0,
                   (struct sockaddr*) &server, sizeof(server)) != rc) {
            perror("sendto error");
            exit(-1);
        }
    }

    return 0;
}
