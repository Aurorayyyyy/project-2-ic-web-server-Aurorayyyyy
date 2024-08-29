#include <bits/types/struct_timespec.h>
// #include <cstddef>
#include <cstddef>
// #include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "parse.h"
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include "pcsa_net.h"
#include <getopt.h>
#include <iostream>
#include <map>
#include <time.h>
#include <functional>
#include <mutex>
#include <vector>
#include <thread>
#include <queue>
#include <condition_variable>
#include <poll.h>
#include <sys/wait.h>

pthread_mutex_t lock_read;




#define BUFSIZE 8192
typedef struct sockaddr SA;

const char* get_ext(char * uri) {
    char* ext;
    ext = strchr(uri,'.');
    if (strcmp((const char*) &uri[strlen(uri) -1], "/") == 0) {
        return "html";
    }
    else if (ext == NULL) {
        return "/index.html";
    }
    return ext+1;
}
std::map<const char*, const char* > validExt= {
    {"html", "text"},
    {"css", "text"},
    {"plain", "text"},
    {"javascript", "text"},
    {"jpg", "image"},
    {"jpeg", "image"},
    {"image", "image"},
    {"gif", "image"},
};

void responeError(int connFd, int errorType) {
    /* errorType - 1 for 404 file not found. 
                 - 2 for 408 connection time out.
                 - 3 for 501 unsupport method.
                 - 4 for 505 bad version. 
                 - 400 for whatefver.
    */
    char buf[BUFSIZE];
    memset(buf, 0,sizeof((buf)));
    
    if (errorType == 1) {
        
        sprintf(buf, "HTTP/1.1 404 File Not Found\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    } else if (errorType == 2) {
        
        sprintf(buf, "HTTP/1.1 408 Connection Time Out\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    } else if (errorType == 3) {
        
        sprintf(buf, "HTTP/1.1 501 Not Implemented\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    } else if (errorType == 4) {
    
        sprintf(buf, "HTTP/1.1 505 Unsupport Method\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    } else if (errorType == 411) {
        sprintf(buf, "HTTP/1.1 411 Do Not have content length\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    } else if (errorType == 500) {
        sprintf(buf, "HTTP/1.1 500 Internal Server broke\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    } else {
        
        sprintf(buf, "HTTP/1.1 400 Error\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
        write_all(connFd, buf, strlen(buf));
    }
}

void respondFile(int connFd, char* uri, char* root, char* method) {
    char link[100];
    strcpy(link, root);
    strcat(link, strcmp(uri, "/") == 0 ? "/index.html" : uri);
    int fd = open(link, O_RDONLY);
    // file not found 
    if (fd == -1) {
        responeError(connFd, 1);
        close(fd);
        return;
    }
    char buf[BUFSIZE];
    ssize_t numRead;
    struct stat sfile;

    fstat(fd, &sfile);

    // Not sure abour this
    // if (sfile.st_size == 0) {
    //     // assume 0 meaning it do not that it did not provide 
    //     responeError(connFd, 411);
    //     close(fd);
    //     return;
    // }

    const char * extension = get_ext(uri);
    const char* extType;
    int isIn = 0;
    for(const auto& [key, value]: validExt) {
        if (strcmp(key, extension) == 0) {
            isIn = 1;
            extType = value;
            break;
        }
    }
    
    if (isIn == 1) {
        char timestr[100];
        struct  timespec ts;
        timespec_get(&ts, TIME_UTC);
        strftime(timestr, sizeof(timestr), "%D %T",gmtime(&sfile.st_mtim.tv_sec));

        char ctimestr[100];
        struct  timespec cts;
        timespec_get(&cts, TIME_UTC);
        
        strftime(ctimestr, sizeof(ctimestr), "%D %T",gmtime(&cts.tv_sec));
        //TODO HANDLE CONTENT LENGTH IF I MISS THEN THROW ERROR 411
        if(strcmp(extType, "text") == 0) {
            sprintf(buf, "HTTP/1.1 200 OK\r\n"
            "Server: ICWS\r\n"
            "Content-length: %lu\r\n"
            "Connection: close\r\n"
            "Date: %s UTC\r\n"
            "Last-Modified: %s UTC\r\n"
            "Content-type: text/%s\r\n\r\n", sfile.st_size, ctimestr,timestr, extension);
        } else if(strcmp(extType, "image") == 0) {
            sprintf(buf, "HTTP/1.1 200 OK\r\n"
            "Server: ICWS\r\n"
            "Content-length: %lu\r\n"
            "Connection: close\r\n"
            "Date: %s UTC\r\n"
            "Last-Modified: %s UTC\r\n"
            "Content-type: image/%s\r\n\r\n", sfile.st_size, ctimestr, timestr, extension);
        }
    } else {
        sprintf(buf, "HTTP/1.1 404 Not Found\r\n"
        "Server: ICWS\r\n"
        "Connection: close\r\n");
    };
    write_all(connFd, buf, strlen(buf));
    
    if (strcmp(method, "GET") == 0) {
        while((numRead = read(fd, buf, BUFSIZE)) > 0) {
            write_all(connFd, buf, numRead);
        }
    }
    close(fd);
}

void fail_exit(char *msg) { fprintf(stderr, "%s\n", msg); exit(-1); }

void responseCGI(int connFd, char* uri, char* root, char* method, char* cgiProgram, char* port, char* body, int timeout) {
     
    std::vector<char*> parameters;
    char* pureURI;
    std::string queryString;
    std::string requestURI;
    std::string str_uri = uri;
    char* ptr = strtok(str_uri.data(), "?");
    requestURI = strdup(ptr);
    while (ptr != NULL) {
        ptr = strtok(NULL,"?");
        if (ptr == NULL) {
            break;
        }
        queryString += strdup(ptr);
        break;
    }
    setenv("QUERY_STRING", queryString.c_str(), 1);

    int c2pFds[2]; /* Child to parent pipe */
    int p2cFds[2]; /* Parent to child pipe */

    // std::cout << "BEGIN CHILD THING\n";
    if (pipe(c2pFds) < 0) fail_exit("c2p pipe failed.");
    if (pipe(p2cFds) < 0) fail_exit("p2c pipe failed.");

    int pid = fork();

    if (pid < 0) fail_exit("Fork failed.");
    
    // std::cout << "BEING CHILD PROCESS\n";
    if (pid == 0) { /* Child - set up the conduit & run inferior cmd */

        /* Wire pipe's incoming to child's stdin */
        /* First, close the unused direction. */
        if (close(p2cFds[1]) < 0) fail_exit("failed to close p2c[1]");
        if (p2cFds[0] != STDIN_FILENO) {
            if (dup2(p2cFds[0], STDIN_FILENO) < 0)
                fail_exit("dup2 stdin failed.");
            if (close(p2cFds[0]) < 0)
                fail_exit("close p2c[0] failed.");
        }

        /* Wire child's stdout to pipe's outgoing */
        /* But first, close the unused direction */
        if (close(c2pFds[0]) < 0) fail_exit("failed to close c2p[0]");
        if (c2pFds[1] != STDOUT_FILENO) {
            if (dup2(c2pFds[1], STDOUT_FILENO) < 0)
                fail_exit("dup2 stdin failed.");
            if (close(c2pFds[1]) < 0)
                fail_exit("close pipeFd[0] failed.");
        }

        char* inferiorArgv[] = {cgiProgram, NULL};
        if (execvpe(cgiProgram, inferiorArgv, environ) < 0) {
            responeError(connFd, 500);
            perror("exec failed.");
            return;
        }
    } 
    else { /* Parent - send a random message */
        /* Close the write direction in parent's incoming */
        if (close(c2pFds[1]) < 0) fail_exit("failed to close c2p[1]");

        /* Close the read direction in parent's outgoing */
        if (close(p2cFds[0]) < 0) fail_exit("failed to close p2c[0]");
        if (strcmp(method, "POST") == 0) {
            char *message = body;
            /* Write a message to the child - replace with write_all as necessary */
            write_all(p2cFds[1], message, strlen(message));
        }
        /* Close this end, done writing. */
        if (close(p2cFds[1]) < 0) fail_exit("close p2c[01] failed.");

        char buf[BUFSIZE+1];
        ssize_t numRead;
        /* Begin reading from the child */
    
        Context temp;
        temp.size = 0;
        int index_of_acutal_buf = 0;
        memset(temp.buf, 0,sizeof((temp.buf)));

        memset(buf, 0,sizeof((buf)));
        int readNum = 0;

        while ((numRead = read_line(c2pFds[0], buf, BUFSIZE, timeout, &temp, &index_of_acutal_buf) )> 0) {
        }

        write_all(connFd, buf, index_of_acutal_buf);
        if (close(c2pFds[0]) < 0) {
            perror("close c2p[01] failed.");
            return;
        }

        /* Wait for child termination & reap */
        int status;

        if (waitpid(pid, &status, 0) < 0)
        {
            perror("waitpid failed.");
            return;
        }
        printf("Child exited... parent's terminating as well.\n");        
    }
    
}

void setTheEnv(Request* request, char* cgiProgram, char* port) {
    

    

    setenv("GATEWAY_INTERFACE","CGI/1.1" , 1);
    setenv("PATH_INFO", cgiProgram, 1);
    // setenv("QUERY_STRING", queryString.c_str(), 1);

    if (strcmp(request->http_method, "POST") != 0) {
        setenv("REQUEST_METHOD" , request->http_method, 1);
    }    
    setenv("REQUEST_URI", request->http_uri, 1);
    setenv("SCRIPT_NAME", "HIGH WAY", 1);
    setenv("SERVER_PORT",  port, 1);
    setenv("SERVER_PROTOCOL","HTTP/1.1" , 1);
    setenv("SERVER_SOFTWARE", "HIGH WAY TO HELL", 1);
    for (int i = 0; i < request->header_count; i ++) {
        const char* header = request->headers[i].header_name;
        if (strcmp(header, "CONTENT_LENGTH")==0)
        {
            setenv("CONTENT_LENGTH", request->headers[i].header_value, 1);    
        }
        else if (strcmp(header, "CONTENT_TYPE")==0)
        {
            setenv("CONTENT_TYPE", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "REMOTE_ADDR")==0)
        {
            setenv("REMOTE_ADDR", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_ACCEPT")==0)
        {
            setenv("REMOTE_ADDR", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_REFERER")==0)
        {
            setenv("HTTP_ACCEPT", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_ACCEPT_ENCODING")==0)
        {
            setenv("HTTP_ACCEPT_ENCODING", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_ACCEPT_LANGUAGE")==0)
        {
            setenv("HTTP_REFERER", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_ACCEPT_CHARSET")==0)
        {
            setenv("HTTP_ACCEPT_ENCODING", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_HOST")==0)
        {
            setenv("HTTP_HOST", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_COOKIE")==0)
        {
            setenv("HTTP_ACCEPT_LANGUAGE", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_USER_AGENT")==0)
        {
            setenv("HTTP_ACCEPT_CHARSET", request->headers[i].header_value, 1);
        }
        else if (strcmp(header, "HTTP_CONNECTION")==0)
        {
            setenv("HTTP_CONNECTION", request->headers[i].header_value, 1);
        }
    }
}


void serve_http(int connFd, char* root, int timeout, char* cgiProgram, char* port) {
    char buf[BUFSIZE];
    
    Context temp;
    temp.size = 0;
    int index_of_acutal_buf = 0;
    memset(temp.buf, 0,sizeof((temp.buf)));

    memset(buf, 0,sizeof((buf)));
    int readNum = 0;
    while ((readNum = read_line(connFd, buf, BUFSIZE, timeout, &temp, &index_of_acutal_buf) )> 0) {
        if (strstr(buf,"\r\n\r\n") != NULL) {
            break;
        }
    }
    if (readNum == -2) {
        responeError(connFd, 2);
        close(connFd);
        return;
    }
    
    pthread_mutex_lock(&lock_read);
    Request *request = parse(buf, index_of_acutal_buf ,connFd);
    pthread_mutex_unlock(&lock_read);
    if (request == NULL) {
        responeError(connFd, 400);
        close(connFd);
        return;
    }

    if (index_of_acutal_buf > BUFSIZE) {
        free(request->headers);
        free(request);
        close(connFd);
        return;
    }
    // Handler CGI
    if (!(strcmp(request->http_version, "HTTP/1.1") == 0 || strcmp(request->http_version, "HTTPS/1.1") == 0)) {
        responeError(connFd, 4);
        free(request->headers);
        free(request);   
    } else if (strncmp(request->http_uri, "/cgi", 4) == 0) {
        std::cout << "begin cgi\n";
        setTheEnv(request, cgiProgram, port);
        if (strcmp(request->http_method, "POST") == 0) {
            std::cout << "FINISH HEADER\n";

            char body[BUFSIZE];

            if (temp.offset < temp.size) {
                int actual_index_body = 0;
                for (int i = temp.offset;  i < temp.size; i++) {
                    body[actual_index_body] = *(temp.buf + i);  
                    actual_index_body++;   
                }
            } else {
                // including the case where size==offset
    
                int index_body = 0;
                Context body_temp;
                body_temp.size = 0;
                memset(body_temp.buf, 0, sizeof(body_temp.buf));

                memset(body, 0, sizeof(body));
                int readBodyNum = 0;
                while ((readBodyNum = read_line(connFd, body, BUFSIZE, timeout, &body_temp, &index_body))> 0) {

                }
    
            }
            responseCGI(connFd, request->http_uri, root, request->http_method, cgiProgram, port, body, timeout);
        }
        else if ((strcmp(request->http_method, "GET") == 0) || (strcmp(request->http_method, "HEAD") == 0) ) {
            std::cout << "PASS TO RESPONSE\n";
            responseCGI(connFd, request->http_uri, root, request->http_method, cgiProgram, port, NULL, timeout);
        } else {
            responeError(connFd, 3);
            free(request->headers);
            free(request);
        }
    
    } else if ((strcmp(request->http_method, "GET") == 0) || (strcmp(request->http_method, "HEAD") == 0)) {
        respondFile(connFd, request->http_uri, root, request->http_method);
        free(request->headers);
        free(request);
    } else {
        responeError(connFd, 3);
        free(request->headers);
        free(request);
    }

    close(connFd);
}

// ref: https://stackoverflow.com/questions/15752659/thread-pooling-in-c11
struct ServStruct {
    int connFd;
    char* root;
    int timeout;
    char* cgiProgram;
    char* port;
};

class ThreadPool {
    public:
        void Start(int num_threads);
        void QueueJob(ServStruct job);
    private:
        void ThreadLoop();
        
        bool should_terminate = false;
        std::mutex queue_mutex;
        std::condition_variable mutex_condition;
        std::vector<std::thread> threads;
        std::queue<ServStruct> jobs;    
};


void ThreadPool::Start(int num_threads) {
    threads.resize(num_threads);
    for (uint32_t i = 0; i < num_threads; i++) {
        threads.at(i) = std::thread([this]() {ThreadLoop();});
    }
}

void ThreadPool::ThreadLoop() {
    while (true) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        mutex_condition.wait(lock, [this] {
            return !jobs.empty();
        });
        ServStruct ser = jobs.front();
        jobs.pop();
        serve_http(ser.connFd, ser.root, ser.timeout, ser.cgiProgram, ser.port);
    }
}

void ThreadPool::QueueJob(ServStruct job) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        jobs.push(job);
    }
    mutex_condition.notify_one();
}
int main(int argc, char **argv){
    int option;
    int option_index = 0;
    char *port = NULL;
    char *root = NULL;
    char *numT = NULL;
    char *timeout = NULL;
    char *cgiProgram = NULL;
    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"root", required_argument, 0, 'r'},
        {"numThreads", required_argument, 0, 'n'},
        {"timeout", required_argument, 0, 't'},
        {"cgiHandler", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    while ((option = getopt_long(argc, argv, "p:r:", long_options, &option_index)) != EOF) {
        switch (option) {
            case 'p':
                port = optarg;
                break;
            case 'r':
                root = optarg;
                break;
            case 'n':
                numT = optarg;
                break;
            case 't':
                timeout = optarg;
                break;
            case 'c':
                cgiProgram = optarg;
                break;
            case '?':
                return 0;
            default:
                return 0;
        }
    }

    int listenFd = open_listenfd(port);
    int index;
    ThreadPool threads;
    threads.Start(atoi(numT));
    int t = atoi(timeout);
    if (pthread_mutex_init(&lock_read, NULL) != 0) {
        printf("\n-------MUTEX INIT FAILED-------\n");
        return 0;
    }
    
    
    for (;;) {
        struct sockaddr_storage clientAddr; // to store addr of the client
        socklen_t clientLen = sizeof(struct sockaddr_storage); // size of the above
        // ...gonna block until someone connects to our socket
        int connFd = accept(listenFd, (SA *) &clientAddr, &clientLen);
        char hostBuf[BUFSIZE], svcBuf[BUFSIZE];
        
        // if (getnameinfo((SA *) &clientAddr, clientLen, hostBuf, BUFSIZE, svcBuf, BUFSIZE, 0) == 0)
            // printf("Connection from %s:%s\n", hostBuf, svcBuf);
        // else
            // printf("Connection from UNKNOWN.");
        ServStruct serv;
        serv.connFd = connFd;
        serv.root = root;
        serv.timeout = t*1000;
        serv.cgiProgram = cgiProgram;
        serv.port = port;
        threads.QueueJob(serv);
        
    }
    return 0;
}
