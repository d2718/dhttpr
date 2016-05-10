#!/usr/bin/python

# dhttpd (.py)
#
# A simple HTTP server daemon, part of a larger architecture.
#
# last update: 2016-05-10

import datetime
import email.utils
import fcntl
import os
import re
import select
import subprocess
import sys
import urllib
import zlib

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# USER-CONFIGURABLE VARIABLES (CONSTANTS (lol)) 
#
# Below are some user-configurable options, listed in rougly descending
# order of configurability-or-configuration likliness.
#
# You probably shouldn't mess with this stuff unless you either know what
# you're doing, or are savvy enough to experiment without hosing stuff.

# Path to the directory where dhttpr is installed. If you want to do the
# absolute minimum amount of configuration, you can just set this, and it
# will probably work just fine.
INSTALL_DIR = '/home/dan/dev/dhttpr'

# The directory where the root URL ('/') is mapped.
WEB_ROOT = os.path.join(INSTALL_DIR, 'web')
# The subdirectory in each USER's home directory where the URL /~USER
# is mapped.
USER_WEBDIR = 'public_html'
# When a directory is requested (as opposed to a file), this is the (ordered)
# list of filenames will seek to serve before it gives up and just serves
# the directory listing.
INDEX_FILENAMES = ['index.html', 'index.php']
# The directory containing auxiliary files
DATA_DIR = os.path.join(INSTALL_DIR, 'dhttpr.d')
# Path to the log file. The DATA_DIR is a good place for this.
LOG_FILE = os.path.join('/tmp/dhttpr.log')
# They way timestamps are written to the log.
LOG_TIME_FORMAT ='%y-%m-%d %H:%M:%S'
# Path to the file containing the header and boilerplate HTML to get sent
# before the directory listing of a directory without an index page.
DIR_INDEX_HEADER = os.path.join(DATA_DIR, 'dir_index_header.html')

# dhttpd will attempt to process requests for files with these extensions
# as cgi scripts if they are executable, otherwise it will just serve
# them as regular files.
CGI_EXTENSIONS = ['.cgi', '.lua', '.php', '.py', '.sh']

# By convention, certain types of files (mainly .php) are automatically
# run through an interpreter by a web server even if they aren't marked as
# executable. This dict maps the file extensions of those types of files
# to the paths of their respective interpreters.
AUTO_INTERPRET = {
    '.php': '/usr/bin/php'
}

# A mapping from HTTP error response codes to the pages served with those
# codes. (Obviously, not every code requires a page to be served with it).
# If a code doesn't have an entry but requires a page served, dhttpd will
# serve the None value.
ERROR_PAGES = {
    '403': os.path.join(DATA_DIR, '403.html'),
    '404': os.path.join(DATA_DIR, '404.html'),
    '500': os.path.join(DATA_DIR, '500.html'),
    '501': os.path.join(DATA_DIR, '501.html'),
    None:  os.path.join(DATA_DIR, 'error.html')
}

# Directory where dhttpd's control pipe and the temporary files written
# and read by dhttpr reside. Somewhere on a tmpfs mount is preferable.
SHM_DIR = '/run/shm/dhttpr'
# The name of the pipe to which dhttpr writes its PID in order to signal
# dhttpd to process a request.
CONTROL_PIPE = os.path.join(SHM_DIR, 'input')

# dhttpd will attempt to guess MIME types based on file extension.
EXT2MIME = {
    '.aif':  'audio/x-aiff',
    '.bin':  'application/octet-stream',
    '.bmp':  'image/bmp',
    '.bz':   'application/x-bzip',
    '.bz2':  'application/x-bzip2',
    '.c':    'text/x-c',
    '.class':   'application/java-vm',
    '.css':  'text/css',
    '.csv':  'text/csv',
    '.deb':  'application/x-debian-package',
    '.dtd':  'application/xml-dtd',
    '.es':   'application/ecmascript',
    '.exe':  'application/x-msdownload',
    '.dvi':  'application/x-dvi',
    '.f':    'text/x-fortran',
    '.gif':  'image/gif',
    '.h216': 'video/h261',
    '.h263': 'video/h263',
    '.h264': 'video/h264',
    '.html': 'text/html',
    '.htm':  'text/html',
    '.ico':  'image/x-icon',
    '.jar':  'application/java-archive',
    '.java': 'text/x-java-source',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.js':   'application/javascript',
    '.json': 'application/json',
    '.mv4':  'video/x-mv4',
    '.pdf':  'application/pdf',
    '.png':  'image/png',
    '.ppd':  'application/vnd.cups.ppd',
    '.sh':   'application/x-sh',
    '.svg':  'image/svg',
    '.swf':  'application/x-shockwave-flash',
    '.txt':  'text/plain',
    '.wad':  'application/x-doom',
    '.xif':  'image/vnd.xiff',
    None:    'binary/octet-stream'
}

# The version of this software, sent in the HTTP response header.
SERVER_HEADER = 'dhttpr v0.4-dev'


# # END OF ANYTHING EVEN REMOTELY USER-CONFIGURABLE
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# This regex parses HTTP headers. Do not alter.
HEADER_RE = re.compile(r'^(\S+):\s+(.+)$')
# This regex is used to recognize PIDs in the control pipe. Do not alter.
DIGITS_RE = re.compile(r'^\d+$')

def log(txt):
    """Writes a message to the log file with a timestamp."""

    timestr = datetime.datetime.now().strftime(LOG_TIME_FORMAT)
    lines = txt.split('\n')
    with open(LOG_FILE, 'a') as f:
        f.write('{t}: {l}\n'.format(t=timestr, l=lines[0]))
        for line in lines[1:]:
            f.write('    {l}\n'.format(l=line))

# This regex is used to find keywords to replace in the d_format() functions
# below. Don't mess.
CHUNK_FORMAT_RE = re.compile(r'{([^}]+)}')

def d_chunk_format(chunk, d):
    """This recursive function does all the heavy lifting for the function
    d_format() below."""

    m = CHUNK_FORMAT_RE.search(chunk)
    if m:
        key = m.group(1)
        start_i = m.start()
        end_i = m.end()
        if key in d:
            return m.string[:start_i] + d[key] + d_chunk_format(m.string[end_i:], d)
        else:
            return m.string[:end_i] + d_chunk_format(m.string[end_i:], d)
    else:
        return chunk

def d_format(txt, d):
    """Similar in function to txt.format(**d), BUT will ignore brace pairs
    that are not on the same line (so C-style code can more easily pass
    through) AND will leave unmatched formatting specifiers in place
    instead of throwing an exception."""

    new_d = dict(d)
    r = [d_chunk_format(x, new_d) for x in txt.split('\n')]
    return '\n'.join(r)

def die(err_code=0):
    """Clean up the conntrol directory and quit."""
    log('die()')
    try:
        subprocess.check_call(['rm', '-r', SHM_DIR])
    except subprocess.CalledProcessError:
        sys.stderr.write('unable to remove SHM directory; it might be still there\n')
    sys.exit(err_code)

def init():
    """Called when the process starts to create the conrol directory and
    maybe configure some other stuff."""
    log('init()')
    if not os.path.isdir(SHM_DIR):
        try:
            subprocess.check_call(['mkdir', SHM_DIR])
            log('created shm dir {d}'.format(d=SHM_DIR))
        except subprocess.CalledProcessError:
            sys.stderr.write('unable to create system directory {d}\n'.format(
                d=SHM_DIR))
            die(2)
    else:
        log('shm dir {d} already present'.format(d=SHM_DIR))
    if not os.path.exists(CONTROL_PIPE):
        try:
            subprocess.check_call(['mkfifo', CONTROL_PIPE])
            log('created control pipe {p}'.format(p=CONTROL_PIPE))
        except subprocess.CalledProcessError:
            sys.stderr.write('unable to create control pipe {p}\n'.format(
                p=CONTROL_PIPE))
            die(2)
    else:
        log('control pipe {p} already present'.format(p=CONTROL_PIPE))

def url2path(url):
    """Convert the portion of the request URL passed to the program into
    a path on the system."""

    chunks = os.path.normpath(url).split(os.path.sep)[1:]
    try:
        if chunks[0][0] == '~':
            base = os.path.expanduser(chunks[0])
            path = os.path.join(base, USER_WEBDIR, *(chunks[1:]))
        else:
            base = WEB_ROOT
            path = os.path.join(base, *chunks)
    except IndexError:
        path = os.path.join(WEB_ROOT, *chunks)
    return path

def ext2content_type(ext):
    return EXT2MIME.get(ext.lower(), EXT2MIME[None])

def path2content_type(path):
    root, ext = os.path.splitext(path)
    return ext2content_type(ext)

def generate_headers(content_type, status='200 OK', extras=None):
    head_strs = [
        'HTTP/1.1 {s}'.format(s=status),
        'Date: {d}'.format(d=email.utils.formatdate(None, False, True)),
        'Server: {s}'.format(s=SERVER_HEADER),
        'Content-type: {ct}'.format(ct=content_type)
    ]
    if extras is not None:
        head_strs.extend(['{k}: {v}'.format(k=x, v=extras[x])
                                     for x in extras])

    return '{h}\n\n'.format(h='\n'.join(head_strs))

def error_path(err_str):
    return ERROR_PAGES.get(err_str, ERROR_PAGES[None])

def serve_dir_index(ostream, url, path):
    """Print a directory listing to ostream.
    url: the URL passed by the request
    path: the path on disk to which the URL corresponds"""

    ostream.write(generate_headers('text/html'))

    listing = os.listdir(path)
    files = {}
    directories = {}
    for fname in listing:
        if fname[0] == '.':
            pass
        else:
            fpath = os.path.join(path, fname)
            stat = os.stat(fpath)
            if os.path.isfile(fpath):
                files[fname] = (str(stat.st_size),
                                datetime.datetime.fromtimestamp(
                                                int(stat.st_mtime)))
            elif os.path.isdir(fpath):
                directories[fname] = datetime.datetime.fromtimestamp(
                                        int(stat.st_mtime))

    dirnames = directories.keys()
    dirnames.sort()
    fnames = files.keys()
    fnames.sort()

    with open(DIR_INDEX_HEADER, 'r') as f:
        header_text = d_format(
                        f.read(),
                        {'title': url})

    ostream.write(header_text)
    ostream.write('<h1>Directory listing of<br>{dwreck}</h1>\n'.format(
        dwreck=url))
    if len(files) + len(directories) == 0:
        ostream.write('<p>This directory listing is empty.</p>\n')
    else:
        ostream.write("""<table>
<tr>
    <th>size</th>
    <th>date</th>
    <th>name</th>
</tr>
""")
        for fname in fnames:
            ostream.write("""<tr>
        <td>{siz}</td>
        <td>{dat}</td>
        <td><a href="{pth}">{nam}</a></td>
    </tr>\n""".format(siz=files[fname][0],
                        dat=files[fname][1],
                        pth=os.path.normpath(url + '//' + fname),
                        nam=fname))
        for fname in dirnames:
            ostream.write("""<tr>
        <td>&nbsp;</td>
        <td>{dat}</td>
        <td><a href="{pth}/">{nam}</a>/</td>
    </tr>\n""".format(dat=directories[fname],
                        pth=os.path.normpath(url + '//' + fname),
                        nam=fname))
        ostream.write('</table>\n')

    ostream.write('</body></html>\n\n')

def dump_file(ostream, path, content_type, extras=None, status='200 OK'):
    """Spit the bytes of the file residing at path down ostream. Path should
    already be verified to exist and be world-(or at least http-server-)
    readable.
    extras parameter should be a dict of any extra response headers
    to be sent."""

    headers = generate_headers(content_type, status, extras)
    ostream.write(headers)
    try:
        with open(path, 'r') as f:
            ostream.write(f.read())
    except IOError:
        log("""ERROR in dump_file(
    ostream={os},
    path={p},
    content_type={ct},
    extras={e},
    status={s}):
Error writing to ostream.""".format(
            os=ostream.name, p=path, ct=content_type,
            e=extras, s=status))

# For CGI environment variables that can come straight from HTTP request
# headers, this maps those variable names to the header names.
ENVIRONMENT_FROM_HEADER = {
    'HTTP_USER_AGENT': 'user-agent',
    'HTTP_REFERRER': 'referer',
    'REMOTE_HOST': 'remote-host'
}

def generate_cgi_environment(path, headers, query, method='GET'):
    """Return a mapping of environment variables to be passed to a CGI script.
    path: the path of the script to be run
    headers: the headers of the HTTP request
    query: the query string
    method: well, as of 2015-04-25, we only use GET"""

    env = {
        'SERVER_SOFTWARE': SERVER_HEADER,
        'REQUEST_METHOD': method,
        'SCRIPT_FILENAME': path,
        'DOCUMENT_ROOT': WEB_ROOT,
    #    'QUERY_STRING': query
    }
    if method=='GET':
        env['QUERY_STRING'] = query
    for ek, ev in ENVIRONMENT_FROM_HEADER.iteritems():
        try:
            env[ek] = headers[ev]
        except KeyError:
            pass
    return env

def serve_autointerpret(ostream, interpreter, path, query, headers, extras):
    log('serve_autointerpret({i}, {p}, &c.)'.format(i=interpreter, p=path))
    try:
        output = subprocess.check_output([interpreter, path],
                                         env=generate_cgi_environment(
                                            path, headers, query))
        ostream.write("""HTTP/1.1 200 OK
Date: {d}
Server: {s}
Content-type: text/html\n
""".format(d=email.utils.formatdate(None, False, True), s=SERVER_HEADER))
        ostream.write(output)
    except subprocess.CalledProcessError as e:
        log("""in serve_autointerpret(): script returned non-zero exit code: {c}
and exception {err}
output (if any): {o}""".format(c=e.returncode, err=e, o=e.output))
        dump_file(ostream, error_path('500'), 'text/html',
              extras, status='500 Internal Server Error')
    except IOError as e:
        log('in serve_autointerpret(): ERR writing to output stream: {err}'.format(
            err=e))
        dump_file(ostream, error_path('500'), 'text/html',
              extras, status='500 Internal Server Error')

def serve_cgi_script(ostream, method, path, query, headers,
                     extras, payload=None):
    """Run the script at path in a subprocess and write the output to ostream.
    path should already be verified as an extant and executable file.
    query: the HTTP query string
    headers: the headers from the HTTP request
    extras: a dict of any extra HTTP response headers to send"""

    log("""serve_cgi_script(path={p},
query={q},
headers={h},
extras={e},
payload={l})""".format(p=path, q=query, h=headers, e=extras, l=payload))
    try:
        cgip = subprocess.Popen(path, env=generate_cgi_environment(
                                            path, headers, query, method),
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        output, err = cgip.communicate(payload)
        ostream.write("""HTTP/1.1 200 OK
Date: {d}
Server: {s}
""".format(d=email.utils.formatdate(None, False, True), s=SERVER_HEADER))
        ostream.write(output)
        if err:
            log("""cgi success w/ stderr output: {e}""".format(e=err))
    except subprocess.CalledProcessError as e:
        log("""in serve_cgi_script(): script returned non-zero exit code: {c}
and exception {err}
output (if any): {o}""".format(c=e.returncode, err=e, o=e.output))
        dump_file(ostream, error_path('500'), 'text/html',
              extras, status='500 Internal Server Error')
    except IOError as e:
        log('in serve_cgi_script(): ERR writing to output stream: {err}'.format(
            err=e))
        dump_file(ostream, error_path('500'), 'text/html',
              extras, status='500 Internal Server Error')

def serve_file(ostream, method, path, query, headers,
               extras=None, payload=None):
    """Serve the file at path to ostream. path should already be verified
    as extant and world- (or at least web-server-) readable. Do the right
    thing if it's a CGI script or if the ETag sent in the request
    matches.
    query: the query string (empty OK)
    headers: dict of the HTTP request headers
    extras: dict of any extra HTTP response headers to send"""

    root, ext = os.path.splitext(path)
    try:
        interpreter_path = AUTO_INTERPRET[ext.lower()]
        serve_autointerpret(ostream, interpreter_path, path, query,
                            headers, extras)
        return
    except KeyError:
        pass
    if ext.lower() in CGI_EXTENSIONS:
        if os.access(path, os.X_OK):
            log('in serve_file(): {p} is executable CGI script'.format(
                p=path))
            serve_cgi_script(ostream, method, path, query, headers,
                             extras, payload)
            return
    content_type = path2content_type(path)
    log('serve_file(): content_type is {ct}'.format(ct=content_type))
    with open(path, 'r') as f:
        etag = str(zlib.adler32(f.read()))
    if extras is not None:
        extras['ETag'] = etag
    else:
        extras = {'ETag': etag}
    try:
        request_etag = headers['if-none-match']
        if etag == request_etag:
            log('serve_file(): ETags match; sending 304')
            ostream.write(
                generate_headers(
                    content_type,
                    '304 Not Modified',
                    extras))
            return
    except KeyError:
        pass
    dump_file(ostream, path, content_type, extras)

def serve_dir(ostream, method, url, path, headers):
    """Serve the directory at path to ostream. path should already be
    verified as extant and readable. If none of the files in the directory
    have approved index filenames (see INDEX_FILENAMES above), just list
    the files.
    url: the URL of the request (that was mapped to path)
    headers: the headers of the HTTP request"""

    for ifn in INDEX_FILENAMES:
        ipth = os.path.join(path, ifn)
        if os.path.isfile(ipth):
            serve_file(ostream, method, ipth, '', headers)
            break
    else:
        serve_dir_index(ostream, url, path)

def serve_get_post(ostream, method, args, headers, payload=None):
    """Send a response down ostream to a GET request.
    args: the 'arguments' to the GET request (the whitespace-separated chunks
          of text after it on the request line)
    headers: the HTTP headers from the request"""

    log('serve_get(): args: {a}'.format(a=args))
    try:
        u, query = args[0].split('?', 1)
    except ValueError:
        u = args[0]
        query = ''
    url = urllib.unquote(u).decode('utf8')
    url_elements = url.split(os.path.sep)
    if '..' in url_elements:
        log('in serve_get(): url contains up-directory (".."); serving 403)')
        dump_file(ostream, error_path('403'), 'text_html',
                    None, '403 Forbidden')
        return
    path = url2path(url)
    if os.path.isfile(path):
        log('serve_get(): serving file {p}'.format(p=path))
        serve_file(ostream, method, path, query, headers, None, payload)
    elif os.path.isdir(path):
        log('serve_get(): serving directory {p}'.format(p=path))
        serve_dir(ostream, method, url, path, headers)
    else:
        log('serve_get(): can\'t serve path {p}; serving error page'.format(
            p=path))
        dump_file(ostream, error_path('404'), 'text/html', None, '404 Not Found')

def respond_to_request(rqid):
    """Respond to the dhttpr process with PID rqid writing its PID to the
    control pipe. Determine type of request and call the appropriate
    function to deal with it.

    As of 2015-04-25, we can only respond to GET requests."""

    ifname = os.path.join(SHM_DIR, rqid + '-q')
    ofname = os.path.join(SHM_DIR, rqid + '-r')
    request_headers = {}
    rq_line = None
    rq_body_lines = []
    try:
        with open(ifname, 'r') as f:
            rq_line = f.readline()
            for line in f.readlines():
                m = HEADER_RE.match(line.strip())
                if m:
                    request_headers[m.group(1).lower()] = m.group(2)
                else:
                    rq_body_lines.append(line)
    except IOError as e:
        log('ERROR in respond_to_request({id}): error reading pipe: {err}'.format(
            id=rqid, err=e))
    request_chunks = rq_line.split()
    rq_body = ''.join(rq_body_lines)
    try:
        if request_chunks[0] == 'GET':
            log('in respond_to_request({id}): serving GET'.format(id=rqid))
            with open(ofname, 'w') as ofile:
                serve_get_post(ofile, 'GET', request_chunks[1:],
                    request_headers)
        elif request_chunks[0] == 'POST':
            log('in respond_to_request({id}): serving POST'.format(id=rqid))
            log('''chunks: {ch}
headers: {h}
body: {b}'''.format(ch=repr(request_chunks),
                    h=repr(request_headers),
                    b=repr(rq_body)))
            with open(ofname, 'w') as ofile:
                serve_get_post(ofile, 'POST', request_chunks[1:],
                request_headers, rq_body)
        else:
            log("""in respond_to_request({id}): too stupid to serve request:
{r}
headers (for good measure): {h}
serving 501""".format(id=rqid, r=rq_line, h=request_headers))
            with open(ofname, 'w') as ofile:
                dump_file(ofile, error_path('501'),
                          'text/html', None, '501 Not Implemented')
    except IndexError:
        log('in respond_to_request(): empty request: {r}'.format(r=rq_line))
        with open(ofname, 'w') as ofile:
            ofile.write(
                generate_headers(
                    'text/plain',
                    '400 Bad Request'))

def main():
    init()
    continue_to_run = True
    while continue_to_run:
        f = open(CONTROL_PIPE, 'r')
        request_pids = f.readlines()
        f.close()
        for line in request_pids:
            cmd = line.strip()
            if cmd == 'EXIT':
                log('in main(): EXIT command rec\'d')
                continue_to_run = False
            elif DIGITS_RE.match(cmd):
                log('in main(): pid {p}'.format(p=cmd))
                respond_to_request(cmd)
            else:
                log('in main(): unknown input in control pipe: {ui}'.format(
                    ui=cmd))
    die()

main()
