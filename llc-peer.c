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

#define MAXLINE   4096
#define SERV_PORT 9596

enum {
    SELECT_FAIL,
    SELECT_TIMEOUT,
    SELECT_PEER_READY,
    SELECT_RELAY_READY,
    SELECT_CLI_READY,
    SELECT_ERROR_READY
};

static int
max(int x, int y, int z)
{
    if (x >= y && x >= z) {
        return x;
    } else if (y >= x && y >= z) {
        return y;
    } else {
        return z;
    }
}

static int
llcPeer_Select(int peerFD, int relayFD, int cliFD, int nfds,
    fd_set recvfds, fd_set errfds, struct timeval timeout)
{
    int result = select(nfds, &recvfds, NULL, &errfds, &timeout);

    if (result == 0) {
        return SELECT_TIMEOUT;
    } else if (result > 0) {
        if (FD_ISSET(peerFD, &recvfds)) {
            return SELECT_PEER_READY;
        } else if (FD_ISSET(relayFD, &recvfds)) {
            return SELECT_RELAY_READY;
        } else if (FD_ISSET(cliFD, &recvfds)) {
            return SELECT_CLI_READY;
        } else if (FD_ISSET(peerFD, &errfds) || FD_ISSET(relayFD, &errfds)
            || FD_ISSET(cliFD, &errfds)) {
            return SELECT_ERROR_READY;
        }
    }
    return SELECT_FAIL;
}

static void
llcPeer_Connect(WOLFSSL* ssl, int peerFD, int relayFD, int cliFD)
{
    // int ret = wolfSSL_connect(ssl);
    // int error = wolfSSL_get_error(ssl, 0);

    int error = SSL_ERROR_WANT_READ;
    int select_ret;

    int ret = SSL_SUCCESS;

    fd_set recvfds, errfds;

    int cliSocket = 0;
    int relaySocket = 0;

    int nfds = max(peerFD, relayFD, cliFD) + 1;
    int startfds = nfds;

    int count = 0;
    while (ret == SSL_SUCCESS) { // && (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)) {
        count++;

        if (error == SSL_ERROR_WANT_READ) {
            // printf("... client would read block\n");
        } else {
            // printf("... client would write block\n");
        }

        FD_ZERO(&recvfds);
        FD_SET(peerFD, &recvfds);
        FD_SET(relayFD, &recvfds);
        FD_SET(cliFD, &recvfds);
        if (cliSocket > 0) {
            FD_SET(cliSocket, &recvfds);
        }
        if (relaySocket > 0) {
            FD_SET(relaySocket, &recvfds);
        }

        FD_ZERO(&errfds);
        FD_SET(peerFD, &errfds);
        FD_SET(relayFD, &errfds);
        FD_SET(cliFD, &errfds);

        // currTimeout = wolfSSL_dtls_get_current_timeout(ssl);
        // select_ret = llcPeer_Select(peerFD, relayFD, cliFD, nfds, recvfds, errfds, timeout);
        printf("block on select\n");
        select_ret = select(nfds, &recvfds, NULL, NULL, NULL); // don't care about errors for now
        // printf("select returned\n");

        if (select_ret >= 0) {
            if (FD_ISSET(peerFD, &recvfds)) {
                printf("peer ready\n");
                ret = wolfSSL_connect(ssl);
                error = wolfSSL_get_error(ssl, 0);
            } else if (FD_ISSET(cliFD, &recvfds)) {
                printf("select returned CLI\n");
                if ((cliSocket = accept(cliFD, NULL, NULL)) == -1) {
                    perror("Error accepting the CLI connection");
                }
                printf("accepted\n");
                fcntl(cliSocket, F_SETFL, O_NONBLOCK);
                // FD_SET(cliFD, &recvfds);
                FD_SET(cliSocket, &recvfds);
                if (cliSocket >= nfds) {
                    nfds = cliSocket + 1;
                }
            } else if (FD_ISSET(relayFD, &recvfds)) {
                printf("relay accepted\n");
                if ((relaySocket = accept(relayFD, NULL, NULL)) == -1) {
                    perror("Error accepting the CLI connection");
                }
                printf("accepted\n");
                fcntl(relaySocket, F_SETFL, O_NONBLOCK);
                // FD_SET(relayFD, &recvfds);
                FD_SET(relaySocket, &recvfds);
                if (relaySocket >= nfds) {
                    nfds = relaySocket + 1;
                }
            } else if (FD_ISSET(cliSocket, &recvfds)) {
                printf("reading data from socket...");
                int rc = 0;
                char buf[100];
                while ((rc = read(cliSocket, buf, sizeof(buf))) > 0) {
                    printf("read %u bytes: %.*s\n", rc, rc, buf);
                }
                printf("done.\n");
                close(cliSocket);
                FD_CLR(cliSocket, &recvfds);
                printf("really done.\n");
                cliSocket = 0;
            } else if (FD_ISSET(relaySocket, &recvfds)) {
                printf("reading data from relay socket...");
                int rc = 0;
                char buf[100];
                while ((rc = read(relaySocket, buf, sizeof(buf))) > 0) {
                    printf("read %u bytes: %.*s\n", rc, rc, buf);
                }
                close(relaySocket);
                FD_CLR(relaySocket, &recvfds);
                relaySocket = 0;
            }
        } else { // socket_ret < 0
            // timeout!
            printf("timeout...\n");
        }

        // else if (select_ret == SELECT_TIMEOUT && !wolfSSL_dtls(ssl)) {
            // error = 2;
        // }
        // } else if (select_ret == SELECT_TIMEOUT && wolfSSL_dtls(ssl) &&
    	//     wolfSSL_dtls_got_timeout(ssl) >= 0) {
        //     error = 2;
        // } else{
        //     error = SSL_FATAL_ERROR;
        // }
    }

    if (ret != SSL_SUCCESS) {
        printf("SSL_connect failed with error %d\n", ret);
    }
}

void
llcPeer_PeerRun(WOLFSSL* ssl)
{
    int n = 0;
    char sendLine[MAXLINE];
    char recvLine[MAXLINE - 1];

    for (;;) {
        while ((n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1)) <= 0) {
	        int readErr = wolfSSL_get_error(ssl, 0);
	        if (readErr != SSL_ERROR_WANT_READ) {
                printf("wolfSSL_read failed");
            }
        }

        // while  ((wolfSSL_write(ssl, sendLine, strlen(sendLine))) != strlen(sendLine)) {
    	//     printf("SSL_write failed");
        // }
    }
}

void
llcPeer_RelayRun(int relayFD)
{
    if (listen(relayFD, 5) == -1) {
        perror("relay listen error");
        exit(-1);
    }

    int cl = 0;
    int rc = 0;
    char buf[100];

    while (1) {
        if ((cl = accept(relayFD, NULL, NULL)) == -1) {
            // perror("relay FD accept error ");
            continue;
        }

        while ((rc = read(cl, buf, sizeof(buf))) > 0) {
            printf("read %u bytes: %.*s\n", rc, rc, buf);
        }

        if (rc == -1) {
            perror("read");
            exit(-1);
        } else if (rc == 0) {
            printf("EOF\n");
            close(cl);
        }
    }
}

void llcPeer_CLIRun(int cliFD)
{
    if (listen(cliFD, 5) == -1) {
        perror("CLI listen error");
        exit(-1);
    }

    int cl = 0;
    int rc = 0;
    char buf[100];

    while (1) {
        if ((cl = accept(cliFD, NULL, NULL)) == -1) {
            // perror("CLI accept error");
            continue;
        }

        while ((rc = read(cl, buf, sizeof(buf))) > 0) {
            printf("read %u bytes: %.*s\n", rc, rc, buf);
        }

        if (rc == -1) {
            perror("read");
            exit(-1);
        } else if (rc == 0) {
            printf("EOF\n");
            close(cl);
        }
    }
}

int
main(int argc, char** argv)
{
    if (argc != 4) {
	    printf("usage: %s <IP address> <relay-name> <cli-name>\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];

    // wolfSSL_Debugging_ON();
    // wolfSSL_Init();
    //
    // WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    // if (ctx == NULL) {
	//     fprintf(stderr, "wolfSSL_CTX_new error.\n");
	//     return EXIT_FAILURE;
    // }
    //
    // char *certs = "peer1.pem";
    // int result = wolfSSL_CTX_load_verify_locations(ctx, certs, 0);
    // if (result != SSL_SUCCESS) {
	//     fprintf(stderr, "Error loading %s, please check the file.\n", certs);
	//     return(EXIT_FAILURE);
    // }
    //
    // WOLFSSL *ssl = wolfSSL_new(ctx);
    // if (ssl == NULL) {
	//     printf("unable to get ssl object");
    //     return 1;
    // }

    struct sockaddr_in peerAddress;
    memset(&peerAddress, 0, sizeof(peerAddress));
    peerAddress.sin_family = AF_INET;
    peerAddress.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, host, &peerAddress.sin_addr) < 1) {
        printf("Error and/or invalid IP address");
        return 1;
    }

    // wolfSSL_dtls_set_peer(ssl, &peerAddress, sizeof(peerAddress));

    int peerFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (peerFD < 0) {
    	printf("Failed to create a socket.");
        return 1;
    }

    // wolfSSL_set_fd(ssl, peerFD);
    // wolfSSL_set_using_nonblock(ssl, 1);
    // fcntl(peerFD, F_SETFL, O_NONBLOCK);

    struct sockaddr_un cliAddressInfo;
    memset(&cliAddressInfo, 0, sizeof(cliAddressInfo));
    cliAddressInfo.sun_family = AF_UNIX;
    strcpy(cliAddressInfo.sun_path, argv[3]);

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

    struct sockaddr_un relayAddressInfo;
    memset(&relayAddressInfo, 0, sizeof(relayAddressInfo));
    relayAddressInfo.sun_family = AF_UNIX;
    strcpy(relayAddressInfo.sun_path, argv[2]);
    printf("relay socket %s\n", argv[2]);

    int relayFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (relayFD < 0) {
        printf("Failed to create a socket.");
        return 1;
    }

    if (bind(relayFD, (struct sockaddr *) &relayAddressInfo, sizeof(struct sockaddr_un))) {
        printf("Failed to bind to CLI socket.");
        return 1;
    }

    if (listen(relayFD, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    fcntl(relayFD, F_SETFL, O_NONBLOCK);

    llcPeer_Connect(NULL, peerFD, relayFD, cliFD);
    // llcPeer_PeerRun(NULL);
    // llcPeer_(relayFD);
    // llcPeer_CLIRun(cliFD);

    // WOLFSSL_SESSION *session = wolfSSL_get_session(ssl);
    // sslResume = wolfSSL_new(ctx);

    // wolfSSL_shutdown(ssl);
    // wolfSSL_free(ssl);
    close(peerFD);
    close(cliFD);
    close(relayFD);

    return 0;
}
