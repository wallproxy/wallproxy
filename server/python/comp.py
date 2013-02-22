#!/usr/bin/env python
# coding=utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '2.1.12'
__password__ = ''
__hostsdeny__ = ()  # __hostsdeny__ = ('.youtube.com', '.youku.com')

import sys
import os
import re
import time
import struct
import zlib
import binascii
import logging
import httplib
import urlparse
import base64
import cStringIO
import hashlib
import hmac
import errno
try:
    from google.appengine.api import urlfetch
    from google.appengine.runtime import apiproxy_errors
except ImportError:
    urlfetch = None
try:
    import sae
except ImportError:
    sae = None
try:
    import socket, select, ssl, thread
except:
    socket = None

FetchMax = 2
FetchMaxSize = 1024*1024*4
DeflateMaxSize = 1024*1024*4
Deadline = 60

def error_html(errno, error, description=''):
    ERROR_TEMPLATE = '''
<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>{{errno}} {{error}}</title>
<style><!--
body {font-family: arial,sans-serif}
div.nav {margin-top: 1ex}
div.nav A {font-size: 10pt; font-family: arial,sans-serif}
span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
div.nav A,span.big {font-size: 12pt; color: #0000cc}
div.nav A {font-size: 10pt; color: black}
A.l:link {color: #6f6f6f}
A.u:link {color: green}
//--></style>

</head>
<body text=#000000 bgcolor=#ffffff>
<table border=0 cellpadding=2 cellspacing=0 width=100%>
<tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Error</b></td></tr>
<tr><td>&nbsp;</td></tr></table>
<blockquote>
<H1>{{error}}</H1>
{{description}}

<p>
</blockquote>
<table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
</body></html>
'''
    kwargs = dict(errno=errno, error=error, description=description)
    template = ERROR_TEMPLATE
    for keyword, value in kwargs.items():
        template = template.replace('{{%s}}' % keyword, value)
    return template

def socket_forward(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, idlecall=None, bitmask=None):
    timecount = timeout
    try:
        while 1:
            timecount -= tick
            if timecount <= 0:
                break
            (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            if ins:
                for sock in ins:
                    data = sock.recv(bufsize)
                    if bitmask:
                        data = ''.join(chr(ord(x)^bitmask) for x in data)
                    if data:
                        if sock is local:
                            remote.sendall(data)
                            timecount = maxping or timeout
                        else:
                            local.sendall(data)
                            timecount = maxpong or timeout
                    else:
                        return
            else:
                if idlecall:
                    try:
                        idlecall()
                    except Exception:
                        logging.exception('socket_forward idlecall fail')
                    finally:
                        idlecall = None
    except Exception:
        logging.exception('socket_forward error')
        raise
    finally:
        if idlecall:
            idlecall()

def socks5_handler(sock, address, hls={'hmac':{}}):
    if not hls['hmac']:
        hls['hmac'] = dict((hmac.new(__password__, chr(x)).hexdigest(),x) for x in xrange(256))
    bufsize = 8192
    rfile = sock.makefile('rb', bufsize)
    wfile = sock.makefile('wb', 0)
    remote_addr, remote_port = address
    MessageClass = dict
    try:
        line = rfile.readline(bufsize)
        if not line:
            raise socket.error('empty line')
        method, path, version = line.rstrip().split(' ', 2)
        headers = MessageClass()
        while 1:
            line = rfile.readline(bufsize)
            if not line or line == '\r\n':
                break
            keyword, _, value = line.partition(':')
            keyword = keyword.title()
            value = value.strip()
            headers[keyword] = value
        logging.info('%s:%s "%s %s %s" - -', remote_addr, remote_port, method, path, version)
        if headers.get('Connection', '').lower() != 'upgrade':
            logging.error('%s:%s Connection(%s) != "upgrade"', remote_addr, remote_port, headers.get('Connection'))
            return
        m = re.search('([0-9a-f]{32})', path)
        if not m:
            logging.error('%s:%s Path(%s) not valid', remote_addr, remote_port, path)
            return
        need_digest = m.group(1)
        bitmask = hls['hmac'].get(need_digest)
        if bitmask is None:
            logging.error('%s:%s Digest(%s) not match', remote_addr, remote_port, need_digest)
            return
        else:
            logging.info('%s:%s Digest(%s) return bitmask=%r', remote_addr, remote_port, need_digest, bitmask)

        wfile.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n')
        wfile.flush()

        rfile_read  = lambda n:''.join(chr(ord(x)^bitmask) for x in rfile.read(n))
        wfile_write = lambda s:wfile.write(''.join(chr(ord(x)^bitmask) for x in s))

        rfile_read(ord(rfile_read(2)[-1]))
        wfile_write(b'\x05\x00');
        # 2. Request
        data = rfile_read(4)
        mode = ord(data[1])
        addrtype = ord(data[3])
        if addrtype == 1:       # IPv4
            addr = socket.inet_ntoa(rfile_read(4))
        elif addrtype == 3:     # Domain name
            addr = rfile_read(ord(rfile_read(1)[0]))
        port = struct.unpack('>H',rfile_read(2))
        reply = b'\x05\x00\x00\x01'
        try:
            logging.info('%s:%s socks5 mode=%r', remote_addr, remote_port, mode)
            if mode == 1:  # 1. TCP Connect
                remote = socket.create_connection((addr, port[0]))
                logging.info('%s:%s TCP Connect to %s:%s', remote_addr, remote_port, addr, port[0])
                local = remote.getsockname()
                reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
            else:
                reply = b'\x05\x07\x00\x01' # Command not supported
        except socket.error:
            # Connection refused
            reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
        wfile_write(reply)
        # 3. Transfering
        if reply[1] == '\x00':  # Success
            if mode == 1:    # 1. Tcp connect
                socket_forward(sock, remote, bitmask=bitmask)
    except socket.error as e:
        if e[0] not in (10053, errno.EPIPE, 'empty line'):
            raise
    finally:
        rfile.close()
        wfile.close()
        sock.close()

def paas_application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        start_response('302 Found', [('Location', 'https://www.google.com')])
        raise StopIteration

    # inflate = lambda x:zlib.decompress(x, -15)
    wsgi_input = environ['wsgi.input']
    data = wsgi_input.read(2)
    metadata_length, = struct.unpack('!h', data)
    metadata = wsgi_input.read(metadata_length)

    metadata = zlib.decompress(metadata, -15)
    headers  = dict(x.split(':', 1) for x in metadata.splitlines() if x)
    method   = headers.pop('G-Method')
    url      = headers.pop('G-Url')

    kwargs   = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    headers['Connection'] = 'close'

    payload = environ['wsgi.input'].read() if 'Content-Length' in headers else None
    if 'Content-Encoding' in headers:
        if headers['Content-Encoding'] == 'deflate':
            payload = zlib.decompress(payload, -15)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    if __password__ and __password__ != kwargs.get('password'):
        random_host = 'g%d%s' % (int(time.time()*100), environ['HTTP_HOST'])
        conn = httplib.HTTPConnection(random_host, timeout=3)
        conn.request('GET', '/')
        response = conn.getresponse(True)
        status_line = '%s %s' % (response.status, httplib.responses.get(response.status, 'OK'))
        start_response(status_line, response.getheaders())
        yield response.read()
        raise StopIteration

    if __hostsdeny__ and urlparse.urlparse(url).netloc.endswith(__hostsdeny__):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield error_html('403', 'Hosts Deny', description='url=%r' % url)
        raise StopIteration

    timeout = Deadline
    xorchar = ord(kwargs.get('xorchar') or '\x00')

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

    if method != 'CONNECT':
        try:
            scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
            HTTPConnection = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
            if params:
                path += ';' + params
            if query:
                path += '?' + query
            conn = HTTPConnection(netloc, timeout=timeout)
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()

            headers = [('X-Status', str(response.status))]
            headers += [(k, v) for k, v in response.msg.items() if k != 'transfer-encoding']
            start_response('200 OK', headers)

            bufsize = 8192
            while 1:
                data = response.read(bufsize)
                if not data:
                    response.close()
                    break
                if xorchar:
                    yield ''.join(chr(ord(x)^xorchar) for x in data)
                else:
                    yield data
        except httplib.HTTPException as e:
            raise

def gae_application(environ, start_response):
    if environ['REQUEST_METHOD'] == 'GET':
        if '204' in environ['QUERY_STRING']:
            start_response('204 No Content', [])
            yield ''
        else:
            timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/pow(2,28)
            ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
            html = u'Python Fetch Server %s \u5df2\u7ecf\u5728\u5de5\u4f5c\u4e86\uff0c\u90e8\u7f72\u65f6\u95f4 %s\n' % (__version__, ctime)
            start_response('200 OK', [('Content-Type', 'text/plain; charset=utf-8')])
            yield html.encode('utf8')
        raise StopIteration

    # inflate = lambda x:zlib.decompress(x, -15)
    wsgi_input = environ['wsgi.input']
    data = wsgi_input.read(2)
    metadata_length, = struct.unpack('!h', data)
    metadata = wsgi_input.read(metadata_length)

    metadata = zlib.decompress(metadata, -15)
    headers  = dict(x.split(':', 1) for x in metadata.splitlines() if x)
    method   = headers.pop('G-Method')
    url      = headers.pop('G-Url')

    kwargs   = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    #logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')
    #logging.info('request headers=%s', headers)

    if __password__ and __password__ != kwargs.get('password', ''):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield error_html('403', 'Wrong password', description='proxy.ini password is wrong!')
        raise StopIteration

    if __hostsdeny__ and urlparse.urlparse(url).netloc.endswith(__hostsdeny__):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield error_html('403', 'Hosts Deny', description='url=%r' % url)
        raise StopIteration

    fetchmethod = getattr(urlfetch, method, '')
    if not fetchmethod:
        start_response('501 Unsupported', [('Content-Type', 'text/html')])
        yield error_html('501', 'Invalid Method: %r'% method, description='Unsupported Method')
        raise StopIteration

    deadline = Deadline
    validate_certificate = bool(int(kwargs.get('validate', 0)))
    headers = dict(headers)
    headers['Connection'] = 'close'
    payload = environ['wsgi.input'].read() if 'Content-Length' in headers else None
    if 'Content-Encoding' in headers:
        if headers['Content-Encoding'] == 'deflate':
            payload = zlib.decompress(payload, -15)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    accept_encoding = headers.get('Accept-Encoding', '')

    errors = []
    for i in xrange(int(kwargs.get('fetchmax', FetchMax))):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, allow_truncated=False, follow_redirects=False, deadline=deadline, validate_certificate=validate_certificate)
            break
        except apiproxy_errors.OverQuotaError as e:
            time.sleep(5)
        except urlfetch.DeadlineExceededError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = Deadline * 2
        except urlfetch.DownloadError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = Deadline * 2
        except urlfetch.ResponseTooLargeError as e:
            response = e.response
            logging.error('ResponseTooLargeError(deadline=%s, url=%r) response(%r)', deadline, url, response)
            m = re.search(r'=\s*(\d+)-', headers.get('Range') or headers.get('range') or '')
            if m is None:
                headers['Range'] = 'bytes=0-%d' % int(kwargs.get('fetchmaxsize', FetchMaxSize))
            else:
                headers.pop('Range', '')
                headers.pop('range', '')
                start = int(m.group(1))
                headers['Range'] = 'bytes=%s-%d' % (start, start+int(kwargs.get('fetchmaxsize', FetchMaxSize)))
            deadline = Deadline * 2
        except urlfetch.SSLCertificateError as e:
            errors.append('%r, should validate=0 ?' % e)
            logging.error('%r, deadline=%s', e, deadline)
        except Exception as e:
            errors.append(str(e))
            if i==0 and method=='GET':
                deadline = Deadline * 2
    else:
        start_response('500 Internal Server Error', [('Content-Type', 'text/html')])
        yield error_html('502', 'Python Urlfetch Error: %r' % method, description='<br />\n'.join(errors) or 'UNKOWN')
        raise StopIteration

    #logging.debug('url=%r response.status_code=%r response.headers=%r response.content[:1024]=%r', url, response.status_code, dict(response.headers), response.content[:1024])

    data = response.content
    if 'content-encoding' not in response.headers and len(response.content) < DeflateMaxSize and response.headers.get('content-type', '').startswith(('text/', 'application/json', 'application/javascript')):
        if 'deflate' in accept_encoding:
            response.headers['Content-Encoding'] = 'deflate'
            data = zlib.compress(data)[2:-4]
        elif 'gzip' in accept_encoding:
            response.headers['Content-Encoding'] = 'gzip'
            compressobj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
            dataio = cStringIO.StringIO()
            dataio.write('\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff')
            dataio.write(compressobj.compress(data))
            dataio.write(compressobj.flush())
            dataio.write(struct.pack('<LL', zlib.crc32(data)&0xFFFFFFFFL, len(data)&0xFFFFFFFFL))
            data = dataio.getvalue()
    response.headers['Content-Length'] = str(len(data))
    response_headers = zlib.compress('\n'.join('%s:%s'%(k.title(),v) for k, v in response.headers.items() if not k.startswith('x-google-')))[2:-4]
    start_response('200 OK', [('Content-Type', 'image/gif')])
    yield struct.pack('!hh', int(response.status_code), len(response_headers))+response_headers
    yield data

app = gae_application if urlfetch else paas_application
application = app if sae is None else sae.create_wsgi_app(app)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    import gevent, gevent.server, gevent.wsgi, gevent.monkey, getopt
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)

    options = dict(getopt.getopt(sys.argv[1:], 'l:p:a:')[0])
    host = options.get('-l', '0.0.0.0')
    port = options.get('-p', '80')
    app  = options.get('-a', 'socks5')

    if app == 'socks5':
        server = gevent.server.StreamServer((host, int(port)), socks5_handler)
    else:
        server = gevent.wsgi.WSGIServer((host, int(port)), paas_application)

    logging.info('serving %s at http://%s:%s/', app.upper(), server.address[0], server.address[1])
    server.serve_forever()
