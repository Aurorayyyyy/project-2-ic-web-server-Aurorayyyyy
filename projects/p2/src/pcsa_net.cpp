#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "pcsa_net.h"
#include <sys/poll.h>
#include <iostream>
#include <vector>

#define LISTEN_QUEUE 5
int open_listenfd(char *port) {
    struct addrinfo hints;
    struct addrinfo* listp;

    memset(&hints, 0, sizeof(struct addrinfo));
    /* Look to accept connect on any IP addr using this port no */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV; 
    int retCode = getaddrinfo(NULL, port, &hints, &listp);

    if (retCode < 0) {
        fprintf(stderr, "Error: %s\n", gai_strerror(retCode));
        exit(-1);
    }

    int listenFd;
    struct addrinfo *p;
    for (p=listp; p!=NULL; p = p->ai_next) {
        if ((listenFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) 
            continue; /* This option doesn't work; try next */

        int optVal = 1;
        /* Alleviate "Address already in use" by allowing reuse */
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR,
                  (const void *) &optVal, sizeof(int));

        if (bind(listenFd, p->ai_addr, p->ai_addrlen) == 0)
            break; /* Yay, success */

        close(listenFd); /* Bind failed, close this, then next */
    }
    
    freeaddrinfo(listp);

    if (!p) 
        return -1; /* None of them worked. Meh */

    /* Make it ready to accept incoming requests */
    if (listen(listenFd, LISTEN_QUEUE) < 0) {
        close(listenFd);
        return -1;
    }

    /* All good, return the file descriptor */
    return listenFd;
}

int open_clientfd(char *hostname, char *port) {
    struct addrinfo hints;
    struct addrinfo* listp;

    memset(&hints, 0, sizeof(struct addrinfo));
    /* Look to accept connect on any IP addr using this port no */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV; 
    int retCode = getaddrinfo(hostname, port, &hints, &listp);

    if (retCode < 0) {
        fprintf(stderr, "Error: %s\n", gai_strerror(retCode));
        exit(-1);
    }

    int clientFd;
    struct addrinfo *p;
    for (p=listp; p!=NULL; p = p->ai_next) {
        if ((clientFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) 
            continue; /* This option doesn't work; try next */

        /* Try connecting */
        if (connect(clientFd, p->ai_addr, p->ai_addrlen) != -1) 
            break; /* Yay, success */

        close(clientFd); /* Bind failed, close this, then next */
    }
    
    freeaddrinfo(listp);

    if (!p) 
        return -1; /* None of them worked. Meh */

    return clientFd;
}

void write_all(int connFd, char *buf, size_t len) {
    size_t toWrite = len;

    while (toWrite > 0) {
        ssize_t numWritten = write(connFd, buf, toWrite);
        if (numWritten < 0) { fprintf(stderr, "Meh, can't write\n"); return ;}
        toWrite -= numWritten;
        buf += numWritten;
    }
}

/* Bad, slow readline */
// ssize_t read_line(int connFd, char *usrbuf, size_t maxlen) {
//     int n;
//     char c, *bufp = usrbuf;

//     for (n = 1; n < maxlen; n++) { 
//         int numRead;
//         if ((numRead = read(connFd, &c, 1)) == 1) {
//             *bufp++ = c;
//             if (c == '\n') { n++; break; }
//         } 
//         else if (numRead == 0) { break; } /* EOF */
//         else return -1;	  /* Error */
//     }
//     *bufp = '\0';
//     return n-1;
// }


ssize_t read_line(int connFd, char *usrbuf, size_t maxlen, int timeout, Context* context, int* index_of_actual_buf) {
    // std::cout << "INSIDE READ LINE\n";
    if (context->size == 0 || context->size == context->offset) {
        // std::cout << "INSIDE POLL CONDITION\n";
        memset(context->buf, 0,sizeof((context->buf)));
        struct pollfd pollFd;
        pollFd.fd = connFd;
        pollFd.events = POLLIN;
        ssize_t readNum;
        // std::cout << "BEFORE POLL\n";
        int pollRet = poll(&pollFd, 1, timeout);
        // std::cout << "AFTER POLL\n";
        if (pollRet < 0) {
            printf("POLL FAIL\n");
        } else if (pollRet == 0) {
            printf("\n=====TIMEOUT======\n");
            return -2;
        }
        readNum = read(connFd, context->buf, maxlen);
        context->size = readNum;
        context->offset = 0;
    }
    int index = 0;
    for (int i = context->offset;  i < context->size; i++) {
        if (*(context->buf + i) == '\n') {
            *(usrbuf + (*index_of_actual_buf)) = *(context->buf + i); 
            context->offset += 1;
            *index_of_actual_buf = (*index_of_actual_buf) + 1;
            index++;
            // std::cout << index << '\n';
            return index;
        }else {
            *(usrbuf + (*index_of_actual_buf)) = *(context->buf + i); 
            context->offset += 1;
            *index_of_actual_buf = (*index_of_actual_buf) + 1;
            index++;
        }
    }
    // std::cout << index << '\n';
    return index;
   
}