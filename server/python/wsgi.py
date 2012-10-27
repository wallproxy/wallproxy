#!/usr/bin/env python
# coding=utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

__version__ = '1.10.1'
__password__ = ''

import sys, os, time, struct, zlib, binascii, logging, httplib, urlparse
try:
    from google.appengine.api import urlfetch
    from google.appengine.runtime import apiproxy_errors, DeadlineExceededError
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
Deadline = 30

def io_copy(source, dest):
    try:
        io_read  = getattr(source, 'read', None) or getattr(source, 'recv')
        io_write = getattr(dest, 'write', None) or getattr(dest, 'sendall')
        while 1:
            data = io_read(8192)
            if not data:
                break
            io_write(data)
    except Exception as e:
        logging.exception('io_copy(source=%r, dest=%r) error: %s', source, dest, e)
    finally:
        pass

def fileobj_to_generator(fileobj, bufsize=8192, gzipped=False):
    assert hasattr(fileobj, 'read')
    if not gzipped:
        while 1:
            data = fileobj.read(bufsize)
            if not data:
                fileobj.close()
                break
            else:
                yield data
    else:
        compressobj = zlib.compressobj(zlib.Z_BEST_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
        crc         = zlib.crc32('')
        size        = 0
        yield '\037\213\010\000' '\0\0\0\0' '\002\377'
        while 1:
            data = fileobj.read(bufsize)
            if not data:
                break
            crc = zlib.crc32(data, crc)
            size += len(data)
            zdata = compressobj.compress(data)
            if zdata:
                yield zdata
        zdata = compressobj.flush()
        if zdata:
            yield zdata
        yield struct.pack('<LL', crc&0xFFFFFFFFL, size&0xFFFFFFFFL)

def httplib_request(method, url, body=None, headers={}, timeout=None):
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    HTTPConnection = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
    if params:
        path += ';' + params
    if query:
        path += '?' + query
    conn = HTTPConnection(netloc, timeout=timeout)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    return response

def paas_application(environ, start_response):
    cookie  = environ['HTTP_COOKIE']
    request = decode_data(zlib.decompress(cookie.decode('base64')))

    url     = request['url']
    method  = request['method']

    logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

    headers = dict((k.title(),v.lstrip()) for k, _, v in (line.partition(':') for line in request['headers'].splitlines()))

    data = environ['wsgi.input'] if int(headers.get('Content-Length',0)) else None

    if method != 'CONNECT':
        try:
            response = httplib_request(method, url, body=data, headers=headers, timeout=16)
            status_line = '%d %s' % (response.status, httplib.responses.get(response.status, 'OK'))

            gzipped = False
##            if response.getheader('content-encoding') != 'gzip' and response.getheader('content-length'):
##                if response.getheader('content-type', '').startswith(('text/', 'application/json', 'application/javascript')):
##                    headers += [('Content-Encoding', 'gzip')]
##                    gzipped = True

            start_response(status_line, response.getheaders())
            return fileobj_to_generator(response, gzipped=gzipped)
        except httplib.HTTPException as e:
            raise

def socket_forward(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, idlecall=None):
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

def paas_socks5(environ, start_response):
    wsgi_input = environ['wsgi.input']
    sock = None
    rfile = None
    if hasattr(wsgi_input, 'rfile'):
        sock = wsgi_input.rfile._sock
        rfile = wsgi_input.rfile
    elif hasattr(wsgi_input, '_sock'):
        sock = wsgi_input._sock
    elif hasattr(wsgi_input, 'fileno'):
        sock = socket.fromfd(wsgi_input.fileno())
    if not sock:
        raise RuntimeError('cannot extract socket from wsgi_input=%r' % wsgi_input)
    # 1. Version
    if not rfile:
        rfile = sock.makefile('rb', -1)
    data = rfile.read(ord(rfile.read(2)[-1]))
    if __password__:
        if '\x02' in data:
            sock.send(b'\x05\x02') # username/password authentication
            data = rfile.read(2)
            data = rfile.read(ord(data[1])+1)
            data = data[:-1], rfile.read(ord(data[-1]))
        if data != ('', __password__):
            # connection not allowed by ruleset
            return sock.send(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
    sock.send(b'\x05\x00')
    # 2. Request
    data = rfile.read(4)
    mode = ord(data[1])
    addrtype = ord(data[3])
    if addrtype == 1:       # IPv4
        addr = socket.inet_ntoa(rfile.read(4))
    elif addrtype == 3:     # Domain name
        addr = rfile.read(ord(sock.recv(1)[0]))
    port = struct.unpack('>H', rfile.read(2))
    reply = b'\x05\x00\x00\x01'
    try:
        logging.info('paas_socks5 mode=%r', mode)
        if mode == 1:  # 1. TCP Connect
            remote = socket.create_connection((addr, port[0]))
            logging.info('TCP Connect to %s:%s', addr, port[0])
            local = remote.getsockname()
            reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
        else:
            reply = b'\x05\x07\x00\x01' # Command not supported
    except socket.error:
        # Connection refused
        reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
    sock.send(reply)
    # 3. Transfering
    if reply[1] == '\x00':  # Success
        if mode == 1:    # 1. Tcp connect
            socket_forward(sock, remote)

def encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(v)) for k, v in dic.iteritems() if v)

def decode_data(qs):
    return dict((k,binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in qs.split('&')))

def send_response(start_response, status, headers, content, content_type='image/gif'):
    strheaders = encode_data(headers)
    #logging.debug('response status=%s, headers=%s, content length=%d', status, headers, len(content))
    if 'content-encoding' not in headers and headers.get('content-type', '').startswith(('text/', 'application/json', 'application/javascript')):
        data = ['1', zlib.compress('%s%s%s' % (struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content))]
    else:
        data = ['0', struct.pack('>3I', status, len(strheaders), len(content)), strheaders, content]
    start_response('200 OK', [('Content-type', content_type), ('Connection', 'keep-alive')])
    return data

def send_notify(start_response, method, url, status, content):
    logging.warning('%r Failed: url=%r, status=%r', method, url, status)
    content = '<h2>Python Server Fetch Info</h2><hr noshade="noshade"><p>%s %r</p><p>Return Code: %d</p><p>Message: %s</p>' % (method, url, status, content)
    return send_response(start_response, status, {'content-type':'text/html'}, content)

def gae_post(environ, start_response):
    request = decode_data(zlib.decompress(environ['wsgi.input'].read(int(environ['CONTENT_LENGTH']))))
    #logging.debug('post() get fetch request %s', request)

    method = request['method']
    url = request['url']
    payload = request['payload']

    if __password__ and __password__ != request.get('password', ''):
        return send_notify(start_response, method, url, 403, 'Wrong password.')

    fetchmethod = getattr(urlfetch, method, '')
    if not fetchmethod:
        return send_notify(start_response, method, url, 501, 'Invalid Method')

    deadline = Deadline

    headers = dict((k.title(),v.lstrip()) for k, _, v in (line.partition(':') for line in request['headers'].splitlines()))
    headers['Connection'] = 'close'

    errors = []
    for i in xrange(FetchMax if 'fetchmax' not in request else int(request['fetchmax'])):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, False, False, deadline, False)
            break
        except apiproxy_errors.OverQuotaError, e:
            time.sleep(4)
        except DeadlineExceededError, e:
            errors.append(str(e))
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            # deadline = Deadline * 2
        except urlfetch.DownloadError, e:
            errors.append(str(e))
            logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            # deadline = Deadline * 2
        except urlfetch.InvalidURLError, e:
            return send_notify(start_response, method, url, 501, 'Invalid URL: %s' % e)
        except urlfetch.ResponseTooLargeError, e:
            logging.error('ResponseTooLargeError(deadline=%s, url=%r)', deadline, url)
            range = request.pop('range', None)
            if range:
                headers['Range'] = range
            else:
                errors.append(str(e))
                return send_notify(start_response, method, url, 500, 'Python Server: Urlfetch error: %s' % errors)
            # deadline = Deadline * 2
        except Exception, e:
            errors.append(str(e))
            # if i==0 and method=='GET':
                # deadline = Deadline * 2
    else:
        return send_notify(start_response, method, url, 500, 'Python Server: Urlfetch error: %s' % errors)

    return send_response(start_response, response.status_code, response.headers, response.content)

def gae_get(environ, start_response):
    timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/pow(2,28)
    ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
    html = u'Python Fetch Server %s \u5df2\u7ecf\u5728\u5de5\u4f5c\u4e86\uff0c\u90e8\u7f72\u65f6\u95f4 %s\n' % (__version__, ctime)
    start_response('200 OK', [('Content-Type', 'text/plain; charset=utf-8')])
    return [html.encode('utf8')]

def app(environ, start_response):
    if urlfetch and environ['REQUEST_METHOD'] == 'POST':
        return gae_post(environ, start_response)
    elif not urlfetch:
        if environ['PATH_INFO'] == '/socks5':
            return paas_socks5(environ, start_response)
        else:
            return paas_application(environ, start_response)
    else:
        return gae_get(environ, start_response)

application = app if sae is None else sae.create_wsgi_app(app)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    import gevent, gevent.pywsgi, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
    def read_requestline(self):
        line = self.rfile.readline(8192)
        while line == '\r\n':
            line = self.rfile.readline(8192)
        return line
    gevent.pywsgi.WSGIHandler.read_requestline = read_requestline
    host, _, port = sys.argv[1].rpartition(':') if len(sys.argv) == 2 else ('', ':', 443)
    if '-ssl' in sys.argv[1:]:
        ssl_args = dict(certfile=os.path.splitext(__file__)[0]+'.pem')
    else:
        ssl_args = dict()
    server = gevent.pywsgi.WSGIServer((host, int(port)), application, log=None, **ssl_args)
    server.environ.pop('SERVER_SOFTWARE')
    logging.info('serving %s://%s:%s/wsgi.py', 'https' if ssl_args else 'http', server.address[0] or '0.0.0.0', server.address[1])
    server.serve_forever()
