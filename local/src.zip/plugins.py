# -*- coding: utf-8 -*-
from __future__ import with_statement

def paas():
    # this part is compatible with goagent 1.1.0 by phus.lu@gmail.com and others
    print 'Initializing PAAS for proxy based on cloud service.'
    set_hosts, Forward = config.import_from('util')
    HeaderDict, Proxy, URLInfo, unparse_netloc, del_bad_hosts = config.import_from(utils)
    import re, zlib, socket, struct, time, random, threading
    from binascii import a2b_hex, b2a_hex
    from base64 import b64encode
    try:
        import ssl
    except ImportError:
        ssl = None

    class HTTPError(Exception):
        #noinspection PyMissingConstructor
        def __init__(self, code, msg):
            self.code = code
            self.msg = msg

        def __str__(self):
            return 'HTTP Error %s: %s' % (self.code, self.msg)

    _range_re = re.compile(r'(\d+)?-(\d+)?')
    _crange_re = re.compile(r'bytes\s+(\d+)-(\d+)/(\d+)')
    def _process_range(headers, max_range):
        range = headers.get('Range', '')
        m = _range_re.search(range)
        if m:
            m = m.groups()
            if m[0]:
                max_range -= 1
                if m[1]:
                    m = 2, int(m[0]), int(m[1])
                    if m[2] - m[1] > max_range:
                        range = 'bytes=%d-%d' % (m[1], m[1] + max_range)
                else:
                    m = 0, int(m[0])
                    range = 'bytes=%d-%d' % (m[1], m[1] + max_range)
            else:
                if m[1]:
                    m = 1, int(m[1])
                    if m[1] > max_range:
                        range = 'bytes=-1024'
                else:
                    m = None,
                    range = 'bytes=0-%d' % (max_range - 1)
        else:
            m = None,
            range = 'bytes=0-%d' % (max_range - 1)
        return m, range

    _setcookie_re = re.compile(r', ([^ =]+(?:=|$))')
    def _fix_setcookie(headers):
        hdr = headers.get('Set-Cookie')
        if hdr:
            headers['Set-Cookie'] = _setcookie_re.sub(r'\r\nSet-Cookie: \1', hdr)
        return headers

    def GAE(**kw):
        self = _GAEHandler
        v = kw.get('appids', '')
        self.appids = v = v.split() if isinstance(v, str) else list(v)
        if not v: raise ValueError('no appids specified')
        scheme = kw.get('scheme', 'http').lower()
        if scheme not in ('http', 'https'):
            raise ValueError('invalid scheme: '+scheme)
        self.url = URLInfo('%s://%s.appspot.com%s?' % (
            scheme, self.appids[0], kw.get('path', '/fetch.py')))
        self.password = kw.get('password', '')
        v = kw.get('proxy', 'default')
        self.proxy = config.global_proxy if v == 'default' else Proxy(v)
        v = kw.get('hosts')
        if v: v = v.split() if isinstance(v, str) else list(v)
        if not v:
            v = ('eJxdztsNgDAMQ9GNIvIoSXZjeApSqc3nUVT3ZojakFTR47wSNEhB8qXhorXg+kM'
                 'jckGtQM9efDKf91Km4W+N4M1CldNIYMu+qSVoTm7MsG5E4KPd8apInNUUMo4bet'
                 'RQjg==').decode('base64').decode('zlib').split('|')
        set_hosts('.appspot.com', v, 0)
        if self.proxy.value:
            self.hosts = v
            self.proxy = self.proxy.new_hosts((v[0], self.url.port))
        self.headers = HeaderDict(kw.get('headers',
            'Content-Type: application/octet-stream'))
        v = kw.get('max_threads', 0)
        self.max_threads = min(10 if v <= 0 else v, len(self.appids))
        self.bufsize = kw.get('bufsize', 8192)
        self.maxsize = kw.get('maxsize', 1000000)
        self.waitsize = kw.get('waitsize', 500000)
        assert self.bufsize <= self.waitsize <= self.maxsize
        self.local_times = kw.get('local_times', 3)
        self.server_times = kw.get('server_times')
        self.fetch_mode = kw.get('fetch_mode', 0)
        self.fetch_args = kw.get('fetch_args', {})
        print '  Init GAE with appids: %s' % '|'.join(self.appids)
        print '  max_threads when range fetch: %d' % self.max_threads
        v = kw.get('listen')
        if v:
            def find_handler(req):
                if req.proxy_type.endswith('http'):
                    return self
            v = data['GAE_server'] = utils.start_new_server(v, find_handler)
            print '  GAE listen on: %s' % unparse_netloc(v.server_address[:2])
        return self

    class GAEHandler(object):
        skip_headers = frozenset(['Proxy-Connection', 'Content-Length', 'Host',
            'Vary', 'Via', 'X-Forwarded-For', 'X-ProxyUser-IP'])

        def build_params(self, req, force_range):
            method = req.command; headers = req.headers
            if method == 'GET':
                req.rangeinfo, range = _process_range(headers, self.maxsize)
                if force_range or req.rangeinfo[0] == 0:
                    headers['Range'] = range
            else:
                req.rangeinfo, range = (None,), ''
            skip_headers = self.skip_headers
            headers.data = dict(kv for kv in headers.iteritems()
                if kv[0] not in skip_headers)
            params = {'url':req.url, 'method':method,
                'headers':headers, 'payload':req.read_body()}
            if range:
                params['range'] = range
            if self.password:
                params['password'] = self.password
            if self.server_times:
                params['fetchmax'] = self.server_times
            return params, dict(self.fetch_args, proxy_auth=req.userid)

        def fetch(self, (params, fetch_args), server=None):
            params = zlib.compress('&'.join(['%s=%s' % (k, b2a_hex(str(v)))
                for k,v in params.iteritems()]), 9)
            errors = []
            url = server or self.url
            opener = self.proxy.get_opener(url, fetch_args)
            ti = si = 0; tend = self.local_times; send = len(self.appids)
            while ti < tend and si < send:
                flag = 0
                try:
                    resp = opener.open(url, params, 'POST', self.headers, 0)
                    if resp.status != 200:
                        resp.close()
                        raise HTTPError(resp.status, resp.reason)
                except Exception, e:
                    opener.close()
                    if isinstance(e, HTTPError):
                        errors.append(str(e))
                        if e.code == 503:
                            errors[-1] = 'Bandwidth Over Quota, please add more APPIDs'
                            ti -= 1
                            if server:
                                url = self.url; server.__init__(url); server = None
                            else:
                                si += 1
                                self.appids.append(self.appids.pop(0)); flag |= 1
                                url.hostname = '%s.appspot.com' % self.appids[0]
                                print 'GAE: switch appid to %s' % self.appids[0]
                        elif e.code == 404:
                            if self.proxy.value:
                                self.hosts.append(self.hosts.pop(0)); flag |= 2
                                print 'GAE: switch host to %s' % self.hosts[0]
                            else:
                                del_bad_hosts()
                        elif e.code == 502:
                            if url.scheme != 'https':
                                ti -= 1
                                url.scheme = 'https'; url.port = 443; flag |= 3
                                print 'GAE: switch scheme to https'
                    elif isinstance(e, socket.error):
                        k = e.args[0]
                        if url.scheme != 'https' and k in (10054, 54, 20054, 104):
                            ti -= 1
                            url.scheme = 'https'; url.port = 443; flag |= 3
                            print 'GAE: switch scheme to https'
                        elif self.proxy.value:
                            errors.append('Connect other proxy failed: %s' % e)
                            self.hosts.append(self.hosts.pop(0)); flag |= 2
                            print 'GAE: switch host to %s' % self.hosts[0]
                        else:
                            errors.append('Connect fetchserver failed: %s' % e)
                            if del_bad_hosts() and k in (10054, 54, 20054, 104, 10047): ti -= 1
                    else:
                        errors.append('Connect fetchserver failed: %s' % e)
                    if flag & 1:
                        url.rebuild()
                    if flag & 2:
                        if self.proxy.value:
                            self.proxy = self.proxy.new_hosts(
                                (self.hosts[0], url.port))
                        opener = self.proxy.get_opener(url, fetch_args)
                else:
                    try:
                        flag = resp.read(1)
                        if flag == '0':
                            code, hlen, clen = struct.unpack('>3I', resp.read(12))
                            headers = HeaderDict([(k, a2b_hex(v))
                                for k,_,v in (x.partition('=')
                                for x in resp.read(hlen).split('&'))])
                            if self.fetch_mode == 1 or (code == 206 and self.fetch_mode == 2):
                                resp = resp.read()
                        elif flag == '1':
                            rawdata = zlib.decompress(resp.read()); resp.close()
                            code, hlen, clen = struct.unpack('>3I', rawdata[:12])
                            headers = HeaderDict([(k, a2b_hex(v))
                                for k,_,v in (x.partition('=')
                                for x in rawdata[12:12+hlen].split('&'))])
                            resp = rawdata[12+hlen:12+hlen+clen]
                        else:
                            raise ValueError('Data format not match(%s)' % url)
                        headers.setdefault('Content-Length', str(clen))
                        return 0, (code, headers, resp)
                    except Exception, e:
                        errors.append(str(e))
                ti += 1
            return -1, errors

        def write_content(self, req, resp, first=False):
            sendall = req.socket.sendall
            if isinstance(resp, str):
                sendall(resp)
            else:
                bufsize = self.bufsize
                data = resp.read(self.waitsize if first else bufsize)
                while data:
                    sendall(data)
                    data = resp.read(bufsize)
                resp.close()

        def need_range_fetch(self, req, headers, resp):
            m = _crange_re.search(headers.get('Content-Range', ''))
            if not m: return None
            m = map(int, m.groups())#bytes %d-%d/%d
            info = req.rangeinfo
            t = info[0]
            if t is None:
                start = 0; end = m[2]; code = 200
                del headers['Content-Range']
            else:
                #noinspection PySimplifyBooleanCheck
                if t == 0: #bytes=%d-
                    start = info[1]; end = m[2]
                elif t == 1: #bytes=-%d
                    start = m[2] - info[1]; end = m[2]
                else: #bytes=%d-%d
                    start = info[1]; end = info[2] + 1
                code = 206
                headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end-1, m[2])
            headers['Content-Length'] = str(end - start)
            req.start_response(code, _fix_setcookie(headers))
            if start == m[0]: #Valid
                return [start, end, m[1] + 1, resp]
            return [start, end, start, None]

        def range_fetch(self, req, params, data):
            params[0].pop('range', None) # disable server auto-range-fetch
            length = data[1] - data[0]
            if self.max_threads > 1 and data[1] - data[2] > self.maxsize:
                handle = self._thread_range
            else:
                handle = self._single_range
            t = time.time()
            if handle(req, params, data):
                t = length / 1000.0 / ((time.time() - t) or 0.0001)
                print '>>>>>>>>>> Range Fetch ended (all @ %sKB/s)' % t
            else:
                req.close_connection = True
                print '>>>>>>>>>> Range Fetch failed'

        #noinspection PyUnboundLocalVariable,PyUnusedLocal
        def _single_range(self, req, params, data):
            start0, end, start, resp = data; del data[:]
            end -= 1; step = self.maxsize; failed = 0; iheaders = params[0]['headers']
            print ('>>>>>>>>>> Range Fetch started%s: bytes=%d-%d, step=%d'
                % (req.proxy_host, start0, end, step))
            if resp:
                self.write_content(req, resp, True)
            while start <= end:
                if failed > 16: return False
                iheaders['Range'] = 'bytes=%d-%d' % (start, min(start+step, end))
                flag, data = self.fetch(params)
                if flag != -1:
                    code, headers, resp = data
                    m = _crange_re.search(headers.get('Content-Range', ''))
                if flag == -1 or code >= 400:
                    failed += 1
                    seconds = random.randint(2*failed, 2*(failed+1))
                    time.sleep(seconds)
                elif 'Location' in headers:
                    failed += 1
                    params[0]['url'] = headers['Location']
                elif not m:
                    failed += 1
                else:
                    print '>>>>>>>>>> %s' % headers['Content-Range']
                    failed = 0
                    self.write_content(req, resp)
                    start = int(m.group(2)) + 1
            return True

        def _thread_range(self, req, params, info):
            tasks, task_size, info, write_content = \
                self._start_thread_range(req, params, info)
            i = 0
            while i < task_size:
                if info[1]: #All threads failed
                    print '>>>>>>>>>> failed@%d bytes=%d-%d' % tuple(info[1][2:5])
                    return False
                task = tasks[i]
                if not isinstance(task[0], int):
                    if task[0]:
                        write_content(task[0], task)
                    i += 1
                    continue
                time.sleep(0.001)
            return True

        def _start_thread_range(self, req, params, info):
            task0, end, start, resp = info; del info[:]
            s = self.maxsize; t = s - 1; tasks = []; i = 1
            while start < end:
                tasks.append([0, set(), i, start, start+t])
                start += s; i += 1
            end -= 1; tasks[-1][-1] = end
            task_size = len(tasks)
            thread_size = min(task_size, self.max_threads)
            lock = threading.Lock(); wlock = threading.Lock()
            info = [1, None, thread_size]
            def write_content(resp, task):
                #noinspection PyBroadException
                try:
                    buf = None
                    if info[0] != task[2] or not wlock.acquire(0):
                        buf = []
                        data = resp.read(8192)
                        while data:
                            buf.append(data)
                            if info[0] == task[2] and wlock.acquire(0):
                                break
                            data = resp.read(8192)
                        else:
                            resp.close()
                            lock.acquire(); task[0] = ''.join(buf); lock.release()
                            return
                    try:
                        info[0] += 1
                        print '>>>>>>>>>> block=%d bytes=%d-%d' % tuple(task[2:5])
                        if buf: req.socket.sendall(''.join(buf))
                        self.write_content(req, resp)
                        task[0] = None
                    finally:
                        wlock.release()
                except:
                    lock.acquire(); del tasks[:]; info[1] = task; lock.release()
            # appids = random.sample(self.appids, thread_size)
            appids = self.appids[1:]; random.shuffle(appids)
            appids.append(self.appids[0]); appids = appids[:thread_size]
            print ('>>>>>>>>>> Range Fetch started: threads=%d blocks=%d '
                'bytes=%d-%d appids=%s' % (thread_size, task_size, task0, end,
                '|'.join(appids)))
            task0 = 0, (), 0, task0, tasks[0][3] - 1
            #noinspection PyBroadException
            try:
                with wlock:
                    for i in xrange(thread_size):
                        t = threading.Thread(target=self._range_thread, args=(
                            appids[i], params, tasks, lock, info, write_content))
                        t.setDaemon(True)
                        t.start()
                    if resp:
                        print '>>>>>>>>>> block=%d bytes=%d-%d' % task0[2:5]
                        self.write_content(req, resp, True)
            except:
                lock.acquire(); del tasks[:]; info[1] = task0; lock.release()
            return tasks, task_size, info, write_content

        def _range_thread(self, server, params, tasks, lock, info, write_content):
            server = URLInfo(self.url, hostname='%s.appspot.com' % server)
            ct = params[0].copy()
            ct['headers'] = headers = HeaderDict(ct['headers'])
            params = ct, params[1]
            ct = threading.current_thread()
            while 1:
                with lock:
                    try:
                        for task in tasks:
                            #noinspection PySimplifyBooleanCheck
                            if task[0] == 0:
                                failed = task[1]
                                if len(failed) == info[2]:
                                    failed.clear()
                                if ct not in failed:
                                    task[0] = 1
                                    break
                        else:
                            for task in tasks:
                                task[1].discard(ct)
                            info[2] -= 1
                            raise StopIteration('No task for me')
                    except StopIteration:
                        break
                headers['Range'] = 'bytes=%d-%d' % (task[3], task[4])
                while 1:
                    if not tasks: return
                    flag, resp = self.fetch(params, server)
                    if not tasks: return
                    if flag != -1 and resp[0] == 206:
                        resp = resp[2]
                        if isinstance(resp, str):
                            lock.acquire(); task[0] = resp; lock.release()
                        else:
                            write_content(resp, task)
                        break
                    with lock:
                        if task[0] >= 2:
                            failed.add(ct); task[0] = 0; break
                        task[0] += 1

        def __call__(self, req, force_range=False):
            req.handler_name = 'GAE'
            params = self.build_params(req, force_range)
            flag, data = self.fetch(params)
            if flag == -1:
                return req.send_error(502, str(data))
            code, headers, resp = data
            if code == 206 and req.command == 'GET':
                data = self.need_range_fetch(req, headers, resp)
                if data:
                    del code, headers, resp
                    return self.range_fetch(req, params, data)
            req.start_response(code, _fix_setcookie(headers))
            self.write_content(req, resp)

    _GAEHandler = GAEHandler()

    def PAAS(**kw):
        self = PAASHandler()
        self.url = url = URLInfo(kw['url'])
        self.password = kw.get('password', '')
        v = kw.get('proxy', 'default')
        self.proxy = config.global_proxy if v == 'default' else Proxy(v)
        self.hosts = None
        v = kw.get('hosts')
        if v:
            v = v.split() if isinstance(v, str) else list(v)
            if self.proxy.value:
                if len(v) > 1: self.hosts = v
                self.proxy = self.proxy.new_hosts((v[0], url.port))
            else:
                set_hosts(url.hostname, v, 0)
        self.headers = HeaderDict(kw.get('headers',
            'Content-Type: application/octet-stream'))
        self.fetch_args = kw.get('fetch_args', {})
        print '  Init PAAS with url: %s' % url
        v = kw.get('listen')
        if v:
            def find_handler(req):
                proxy_type = req.proxy_type
                if proxy_type.endswith('http'):
                    return self
                proxy = self.proxy
                if proxy.https_mode and not proxy.userid and proxy_type == 'https':
                    return self.try_https_auth
            v = data['PAAS_server'] = utils.start_new_server(v, find_handler)
            print '  PAAS listen on: %s' % unparse_netloc(v.server_address[:2])
        return self

    class PAASHandler(object):
        def __call__(self, req):
            req.handler_name = 'PAAS'
            params = {'method':req.command, 'url':req.url, 'headers':req.headers}
            if self.password:
                params['password'] = self.password
            params = '&'.join(['%s=%s' % (k, b2a_hex(str(v)))
                for k,v in params.iteritems()])
            self.headers['Cookie'] = b64encode(zlib.compress(params, 9))
            url = self.url
            try:
                resp = self.proxy.get_opener(url, 
                        dict(self.fetch_args, proxy_auth=req.userid)).open(
                    url, req.read_body(), 'POST', self.headers, 0)
            except Exception, e:
                if self.hosts:
                    self.hosts.append(self.hosts.pop(0))
                    print 'PAAS: switch host to %s' % self.hosts[0]
                    self.proxy = self.proxy.new_hosts((self.hosts[0], url.port))
                    return req.send_error(502, 'Connect other proxy failed: %s' % e)
                return req.send_error(502, 'Connect fetchserver failed: %s' % e)
            req.start_response(resp.status, _fix_setcookie(resp.msg), resp.reason)
            sendall = req.socket.sendall
            data = resp.read(8192)
            while data:
                sendall(data)
                data = resp.read(8192)
            resp.close()

        def try_https_auth(self, req):
            url = self.url
            try:
                resp = self.proxy.get_opener(url,
                        dict(self.fetch_args, proxy_auth=req.userid)).open(
                    url, '', 'POST', self.headers, 0)
            except Exception, e:
                return req.send_error(502, ('Connect fetchserver failed: %s' % e))
            resp.read()
            if resp.status != 407:
                return req.fake_https()
            if 'keep-alive' in resp.msg.get('Proxy-Connection', '').lower():
                req.close_connection = False
            resp.msg['Content-Length'] = '0'
            req.socket.sendall('HTTP/1.0 %d %s\r\n%s\r\n' % (
                resp.status, resp.reason, resp.msg))
            resp.close()

    def SOCKS5(**kw):
        self = SOCKS5Handler()
        url = URLInfo(kw['url'])
        self.scheme = url.scheme
        self.host = url.host
        self.path = url.path
        v = kw.get('password')
        self.auth = v if v is None else ('',v)
        v = kw.get('proxy', 'default')
        self.proxy = config.global_proxy if v == 'default' else Proxy(v)
        if self.scheme == 'https' and self.proxy.https_mode:
            self.proxy = self.proxy.https_mode
        self.value = self.hosts = None
        v = kw.get('hosts')
        if v:
            v = v.split() if isinstance(v, str) else list(v)
            if self.proxy.value:
                if len(v) > 1: self.hosts = v
                self.value = [v[0], url.port]
            else:
                set_hosts(url.hostname, v, 0)
        if not self.value:
            self.value = url.hostname, url.port
        print '  Init SOCKS5 with url: %s' % url
        self = Forward(self)
        self.handler_name = 'SOCKS5'
        v = kw.get('listen')
        if v:
            v = data['SOCKS5_server'] = utils.start_new_server(v, lambda req:self)
            print '  SOCKS5 listen on: %s' % unparse_netloc(v.server_address[:2])
        return self

    class SOCKS5Handler(Proxy):
        __new__ = object.__new__

        def connect(self, addr, timeout, cmd=1):
            try:
                sock = self.proxy.connect(self.value, timeout, 1)
            except Exception:
                if self.hosts:
                    self.hosts.append(self.hosts.pop(0))
                    print 'SOCKS5: switch host to %s' % self.hosts[0]
                    self.value[0] = self.hosts[0]
                raise
            if self.scheme == 'https':
                try:
                    sock = ssl.wrap_socket(sock)
                except Exception, e:
                    raise socket.error(e)
            sock.sendall('PUT %s HTTP/1.1\r\nHost: %s\r\n'
                'Connection: Keep-Alive\r\n\r\n' % (self.path, self.host))
            addr = self.handlers['socks5'](
                sock, sock.makefile('rb', 0), self.auth, 0, addr, cmd)
            return self._proxysocket(sock, addr)

    globals().update(GAE=GAE, PAAS=PAAS, SOCKS5=SOCKS5)

def third(daemons={}, modules=[]):
    print '-' * 78
    print 'Initializing third for other python applications.'

    import sys, os, thread, time
    from types import ModuleType

    del modules[:]

    def run(*argv, **kw):
        if not argv or argv in daemons: return
        mod = daemons[argv] = ModuleType('__main__')
        def register_stop(cb):
            config.server_stop.append(cb)
            modules.append(daemons.pop(argv))
        mod.register_stop = register_stop
        mod.__file__ = argv[0]
        import __main__ as sysmain
        sysdir = os.getcwd(); os.chdir(utils.misc_dir)
        sysargv = sys.argv[:]; syspath = sys.path[:]
        sys.path.insert(0, os.path.abspath(os.path.dirname(argv[0])))
        sys.argv[:] = argv; sys.modules['__main__'] = mod
        try:
            thread.start_new_thread(execfile, (argv[0], mod.__dict__))
            time.sleep(kw.get('wait', 5))
        finally:
            os.chdir(sysdir)
            sys.modules['__main__'] = sysmain
            sys.argv[:] = sysargv; sys.path[:] = syspath
            if getattr(mod, 'register_stop', None) is register_stop:
                del mod.register_stop

    globals().update(run=run)

def misc():
    import os

    def Page(file):
        HeaderDict = utils.HeaderDict
        version = utils.__version__
        listen = 'http://%s/' % utils.unparse_netloc(utils.get_main_address(), 80)
        file = os.path.join(utils.misc_dir, file)
        try:
            with open(file, 'rb') as fp: tpl = fp.read()
        except IOError:
            tpl = ''
        def handler(req):
            req.handler_name = 'PAGE'
            if req.content_length > 1 * 1024 * 1024:
                return req.send_error(413)
            data = tpl.format(listen=listen, version=version, req=req,
                    server=req.server_address, client=req.client_address,
                    method=req.command, url=req.url, headers=req.headers,
                    body=req.read_body())
            headers = HeaderDict()
            headers['Content-Length'] = str(len(data))
            req.start_response(200, headers)
            req.socket.sendall(data)
        return handler

    globals().update(Page=Page)
