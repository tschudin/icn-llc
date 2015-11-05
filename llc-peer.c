// llc-peer.c

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/ssl.h>
#include <wolfssl/options.h>

#define MSGLEN 1024
#define SERV_PORT 9001

#include "llc-cmd.c"

static int llcPeer_Connect(int listenFD);
static int llcPeer_CreateListener(WOLFSSL_CTX *context);

char *icnllc_path = "/tmp/icn-llc.fifo";

enum {
    SELECT_FAIL,
    SELECT_TIMEOUT,
    SELECT_PEER_READY,
    SELECT_RELAY_READY,
    SELECT_CLI_READY,
    SELECT_ERROR_READY
};


struct session_s {
    int cliFD;
    int relayFD;
    int listenerFD;
    struct WOLFSSL_CTX *listenerCtx;
    struct WOLFSSL_CTX *senderCtx;
} theSession;

static int
max(int *x, int len)
{
    int maxNum = x[0];
    for (int i = 1; i < len; i++) {
        if (x[i] > maxNum) {
            maxNum = x[i];
        }
    }
    return maxNum;
}

static int
llcPeer_Select(int listenerFD, int relayFD, int cliFD, int nfds,
    fd_set recvfds, fd_set errfds, struct timeval timeout)
{
    int result = select(nfds, &recvfds, NULL, &errfds, &timeout);

    if (result == 0) {
        return SELECT_TIMEOUT;
    } else if (result > 0) {
        if (FD_ISSET(listenerFD, &recvfds)) {
            return SELECT_PEER_READY;
        } else if (FD_ISSET(relayFD, &recvfds)) {
            return SELECT_RELAY_READY;
        } else if (FD_ISSET(cliFD, &recvfds)) {
            return SELECT_CLI_READY;
        } else if (FD_ISSET(listenerFD, &errfds) || FD_ISSET(relayFD, &errfds)
            || FD_ISSET(cliFD, &errfds)) {
            return SELECT_ERROR_READY;
        }
    }
    return SELECT_FAIL;
}

static void
llcPeer_Run(struct session_s *sp)
{
    int select_ret;
    fd_set recvfds, errfds;
    int nfds = max(sp->listenerFD, sp->relayFD, sp->cliFD) + 1;

    // There is only one CLI socket.
    int cliSocket = 0;

    // There can be many peer relay sockets.
    int *relaySockets = (int *) malloc(sizeof(int) * 1);
    relaySockets[0] = 0;

    //
    int *descriptors = (int *) malloc(sizeof(int) * 3);
    descriptors[0] = listenerFD;
    descriptors[1] = relayFD;
    descriptors[2] = cliFD;
    int nfds = max(descriptors, 3) + 1;

    for (;;) {
        FD_ZERO(&recvfds);
        FD_SET(sp->listenerFD, &recvfds);
        FD_SET(sp->relayFD, &recvfds);
        FD_SET(sp->cliFD, &recvfds);
        //        FD_SET(cliFD, &recvfds);
        /*
        if (cliSocket > 0) {
            FD_SET(cliSocket, &recvfds);
        }
        if (relaySocket > 0) {
            FD_SET(relaySocket, &recvfds);
        }
        */

        FD_ZERO(&errfds);
        FD_SET(sp->listenerFD, &errfds);
        FD_SET(sp->relayFD, &errfds);
        FD_SET(sp->cliFD, &errfds);

        select_ret = select(nfds, &recvfds, NULL, &errfds, NULL);
        // we don't care about errors (in errfds) for now

        if (select_ret >= 0) {
            if (FD_ISSET(sp->listenerFD, &recvfds)) {
                // activity on the listening socket, there's a new
                // connection attempt, so go ahead with it.
                int newlistenerFD = llcPeer_Connect(sp->listenerFD);
//                WOLFSSL *ssl = wolfSSL_new(ctx);
                WOLFSSL *ssl = NULL;
                if (ssl == NULL) {
                    printf("wolfSSL_new error.\n");
                } else {
                    wolfSSL_set_fd(ssl, newlistenerFD);
                    wolfSSL_set_using_nonblock(ssl, 1);

                    fd_set listenfds;
                    FD_ZERO(&listenfds);
                    FD_SET(newlistenerFD, &listenfds);
                    struct timeval timeout = { 1, 0 };
                    int ret = -1;
                    int error = -1;

                    for (int i = 0; i < 5; i++) {
                        int result = select(newlistenerFD + 1, &listenfds, NULL, NULL, &timeout);
                        if (result > 0 && FD_ISSET(newlistenerFD, &listenfds)) {
                            ret = wolfSSL_accept(ssl);
                            error = wolfSSL_get_error(ssl, 0);
                            break;
                        }
                    }

                    if (ret == -1 && error == -1) {
                        // timeout
                    } else {
                        printf("Connected!\n");
                        // connected.... use wolfSSL_read and wolfSSL_write for IO
                    }
                }
            } else if (FD_ISSET(sp->cliFD, &recvfds)) {
                rl_callback_read_char();
            } else if (FD_ISSET(sp->relayFD, &recvfds)) {
                if ((relaySocket = accept(sp->relayFD, NULL, NULL)) == -1) {
                    perror("Error accepting the RELAY connection");
                }
                fcntl(relaySocket, F_SETFL, O_NONBLOCK);
                FD_SET(relaySocket, &recvfds);
                if (relaySocket >= nfds) {
                    nfds = relaySocket + 1;
                }
            }
        } else {
            // pass: timeout
        }
    }
}

void
llcPeer_SetSocketNonBlocking(int *sockfd)
{
    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0) {
        printf("fcntl get failed");
    }
    flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0) {
        printf("fcntl set failed.\n");
    }
}

int
llcPeer_CreateListener(WOLFSSL_CTX *context)
{
    int listenFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenFD < 0 ) {
        printf("Cannot create socket.\n");
        return 1;
    }

    printf("Socket allocated\n");

    llcPeer_SetSocketNonBlocking(&listenFD);

    struct sockaddr_in servAddr;
    memset((char *)&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(SERV_PORT);

    int on = 1;
    int len = sizeof(on);
    int res = setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &on, len);
    if (res < 0) {
        printf("Setsockopt SO_REUSEADDR failed.\n");
        return 1;
    }

    if (bind(listenFD, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        printf("Bind failed.\n");
        return 1;
    }

    return listenFD;
}

static int
llcPeer_Connect(int listenFD)
{
    int bytesRecvd;
    unsigned char  b[MSGLEN];
    struct sockaddr_in cliAddr;
    socklen_t clilen = sizeof(cliAddr);

    do {
        bytesRecvd = (int)recvfrom(listenFD, (char*)b, sizeof(b), MSG_PEEK, (struct sockaddr*)&cliAddr, &clilen);
    } while (bytesRecvd <= 0);

    if (bytesRecvd > 0) {
        if (connect(listenFD, (const struct sockaddr*) &cliAddr, sizeof(cliAddr)) != 0) {
            printf("udp connect failed.\n");
        }
    } else {
        printf("recvfrom failed.\n");
    }

    printf("Connected!\n");
    memset(&b, 0, sizeof(b));

    return listenFD;


    // WOLFSSL_CTX *clientContext = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    // if (clientContext == NULL) {
        //     fprintf(stderr, "wolfSSL_CTX_new error.\n");
        //     return EXIT_FAILURE;
    // }
    //
    // char *certs = "certs/ca-cert.pem";
    // int result = wolfSSL_CTX_load_verify_locations(clientContext, certs, 0);
    // if (result != SSL_SUCCESS) {
        //     fprintf(stderr, "Error loading %s, please check the file.\n", certs);
        //     return(EXIT_FAILURE);
    // }
    //
    // WOLFSSL *ssl = wolfSSL_new(clientContext);
    // if (ssl == NULL) {
        //     printf("unable to get ssl object");
    //     return 1;
    // }
    //
    // struct sockaddr_in peerAddress;
    // memset(&peerAddress, 0, sizeof(peerAddress));
    // peerAddress.sin_family = AF_INET;
    // peerAddress.sin_port = htons(port);
    // if (inet_pton(AF_INET, host, &peerAddress.sin_addr) < 1) {
    //     printf("Error and/or invalid IP address");
    //     return 1;
    // }
    //
    // wolfSSL_dtls_set_peer(ssl, &peerAddress, sizeof(peerAddress));
    //
    // int listenerFD = socket(AF_INET, SOCK_DGRAM, 0);
    // if (listenerFD < 0) {
    // 	printf("Failed to create a socket.");
    //     return 1;
    // }
    //
    // wolfSSL_set_fd(ssl, listenerFD);
    // wolfSSL_set_using_nonblock(ssl, 1);
    // fcntl(listenerFD, F_SETFL, O_NONBLOCK);
    //
    // int ret = wolfSSL_connect(ssl);
    // int error = wolfSSL_get_error(ssl, 0);
}

int
dtls_setup(char *host, WOLFSSL_CTX **ctx)
{
    char caCertLoc[] = "certs/ca-cert.pem";
    char servCertLoc[] = "certs/server-cert.pem";
    char servKeyLoc[] = "certs/server-key.pem";

    wolfSSL_Debugging_ON();
    wolfSSL_Init();

#ifdef BUGGY
    *ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    if (*ctx == NULL) {
        printf("wolfSSL_CTX_new error.\n");
        return -1;
    }

    if (wolfSSL_CTX_load_verify_locations(*ctx, caCertLoc, 0) != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", caCertLoc);
        return -1;
    }
    if (wolfSSL_CTX_use_certificate_file(*ctx, servCertLoc, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", servCertLoc);
        return -1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(*ctx, servKeyLoc, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", servKeyLoc);
        return -1;
    }
#endif

   return llcPeer_CreateListener(*ctx);
}

int
relay_setup(char *fifoname)
{
    int relayFD;
    struct sockaddr_un relayAddressInfo;

    unlink(fifoname);
    memset(&relayAddressInfo, 0, sizeof(relayAddressInfo));
    relayAddressInfo.sun_family = AF_UNIX;
    strcpy(relayAddressInfo.sun_path, fifoname);

    relayFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (relayFD < 0) {
        printf("Failed to create a socket.");
        return -1;
    }

    if (bind(relayFD, (struct sockaddr *) &relayAddressInfo,
                                                  sizeof(struct sockaddr_un))) {
        printf("Failed to bind to CLI socket.");
        return -1;
    }

    if (listen(relayFD, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    fcntl(relayFD, F_SETFL, O_NONBLOCK);

    return relayFD;
}

// ----------------------------------------------------------------------

void readline_start(int linecnt);

void
cmd_doit(char *line)
{
    if (!llc_execute(line))
        readline_start(linecnt);
    else {
        printf("\n* llc-cmd ends here.\n");
        exit(0);
    }
}

void
readline_start(int linecnt)
{
    char prompt[20], *line;

    sprintf(prompt, "llc %d> ", linecnt);
    rl_callback_handler_install(prompt, cmd_doit);
}

int
console_setup(char *fifoname)
{
    printf("ICN-LLC command console\n\n");
    readline_start(0);

    /*
#ifdef XXX
    struct sockaddr_un cliAddressInfo;

    memset(&cliAddressInfo, 0, sizeof(cliAddressInfo));
    cliAddressInfo.sun_family = AF_UNIX;
    strcpy(cliAddressInfo.sun_path, fifoname);

    int cliFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cliFD < 0) {
            printf("Failed to create a socket.");
        return 1;
    }

    if (bind(cliFD, (struct sockaddr *) &cliAddressInfo, sizeof(struct sockaddr_un))) {
        printf("Failed to bind to CLI socket.");
        return 1;
    }

    if (listen(cliFD, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    fcntl(cliFD, F_SETFL, O_NONBLOCK);
    */
    return 0;
}

// ----------------------------------------------------------------------

int
main(int argc, char** argv)
{
    struct session_s *sp = &theSession;
//    int listenerFD, relayFD, cliFD;
//    WOLFSSL_CTX *peerListenerCtx = NULL;

    if (argc != 3) {
        printf("usage: %s <relay-fifoname> <cli-fifoname>\n", argv[0]);
        return 1;
    }

    using_history();
    nsroot = init();

/*
    listenerFD = dtls_setup(argv[1], &peerListenerCtx);
    if (listenerFD < 0)
        return listenerFD;
*/

    sp->relayFD = relay_setup(argv[1]);
    if (sp->relayFD < 0)
        return sp->relayFD;

    sp->cliFD = console_setup(argv[2]);

    sp->listenerFD = llcPeer_CreateListener(peerListenerCtx);
    llcPeer_Run(peerListenerCtx, peerClientCtx, listenerFD, relayFD, cliFD);


    // WOLFSSL_SESSION *session = wolfSSL_get_session(ssl);
    // sslResume = wolfSSL_new(ctx);

    // wolfSSL_shutdown(ssl);
    // wolfSSL_free(ssl);

    close(sp->listenerFD);
    close(sp->listenerFD);
    //    close(sp->cliFD);
    close(sp->relayFD);

    return 0;
}
