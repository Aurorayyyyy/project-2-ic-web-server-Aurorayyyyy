#ifndef __PCSA_NET_
#define __PCSA_NET_
#include <unistd.h>
#include <iostream>
#include <vector>

#define BUFSIZE 8192
struct Context {
    char buf[BUFSIZE];
    size_t size;
    int offset;  
};
int open_listenfd(char *port);
int open_clientfd(char *hostname, char *port);
ssize_t read_line(int connFd, char *usrbuf, size_t maxlen, int timeout, Context* temp, int* index_of_actual_buf);
void write_all(int connFd, char *buf, size_t len);

#endif
