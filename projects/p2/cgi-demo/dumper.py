#!/usr/bin/env python3

from os import environ
import cgi, cgitb

if __name__ == '__main__':
    CRLF = '\r\n'
    print("WHAT");
    cgitb.enable()

    print('HTTP/1.1 200 OK', end=CRLF)
    print(f'Server: {environ["SERVER_SOFTWARE"]}', end=CRLF)
    cgi.test() # complete the rest of the headers and terminate the header too
