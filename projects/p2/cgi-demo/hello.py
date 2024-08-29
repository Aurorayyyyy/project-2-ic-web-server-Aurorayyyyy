#!/usr/bin/env python3

from os import environ
import cgi, cgitb, sys

CRLF = '\r\n'

cgitb.enable()

def print_line(fin, fout):
    data = fin.read()
    if len(data) != 0:
        print(f'{repr(data)}', file=fout)

query = cgi.FieldStorage()
name = query.getfirst('name', 'Unknown')

print('HTTP/1.1 200 OK', end=CRLF)
print(f'Server: {environ["SERVER_SOFTWARE"]}', end=CRLF)
print(end=CRLF)

print('<html><body>')
print('<h1>Hello!</h1>')

print_line(sys.stdin, sys.stdout)

print(f'<h2>Nice to meet you, {name}!</h2>')
print('</body></html>')
