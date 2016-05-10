#!/usr/bin/python

# dhttpr (.py)
#
# A relatively lightweight process that queues and relays requests from
# inetd to dhttpd.py, then relays the responses back.
#
# last update: 2016-05-10
 
import os
import sys

CHUNK_SIZE = 4096

SHM_DIR = '/run/shm/dhttpr'
CONTROL_PIPE = os.path.join(SHM_DIR, 'input')
PID = str(os.getpid())
ofname = os.path.join(SHM_DIR, PID + '-q')
ifname = os.path.join(SHM_DIR, PID + '-r')
ERR_DUMP_DIR = '/tmp'

try:
    request_line = sys.stdin.readline().strip()
    header_lines = ['Remote-Host: ' + os.environ['REMOTE_HOST']]
    cont = True
    length = 0
    msg_body = ''
    while cont:
        line = sys.stdin.readline().strip()
        if line.lower()[:16] == 'content-length: ':
            length = int(line[16:])
        if line == '':
            if length > 0:
                msg_body = sys.stdin.read(length)
            cont = False
        else:
            header_lines.append(line)

    os.mkfifo(ifname)

    with open(ofname, 'w') as f:
        f.write(request_line +'\n')
        f.write('\n'.join(header_lines))
        if length > 0:
            f.write('\n')
            f.write(msg_body)

    with open(CONTROL_PIPE, 'w') as f:
        f.write(PID + '\n')

    with open(ifname, 'r') as f:
        chunk = f.read(CHUNK_SIZE)
        while chunk != '':
            sys.stdout.write(chunk)
            chunk = f.read(CHUNK_SIZE)
except Exception as e:
    sys.stdout.write("""HTTP/1.1 500 Internal Server Error
Content-type: text/plain

Error 500: Something went horribly wrong with the server.\n""")
    sys.stderr = open(os.path.join(ERR_DUMP_DIR, str(PID) + '.err'))
    raise e
finally:
    try:
        os.remove(ofname)
        os.remove(ifname)
    except Exception:
        sys.stderr.write('unable to remove file/fifo; also...\n')
