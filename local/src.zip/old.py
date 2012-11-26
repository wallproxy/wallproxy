# -*- coding: utf-8 -*-

def old():
    import_from, global_proxy = config.import_from(config)

    # ================================ util.crypto =================================
    import hashlib, itertools

    class XOR:
        '''XOR with pure Python in case no PyCrypto'''
        def __init__(self, key):
            self.key = key

        def encrypt(self, data):
            xorsize = 1024
            key = itertools.cycle(map(ord, self.key))
            dr = xrange(0, len(data), xorsize)
            ss = [None] * len(dr)
            for i,j in enumerate(dr):
                dd = [ord(d)^k for d,k in itertools.izip(data[j:j+xorsize], key)]
                ss[i] = ''.join(map(chr, dd))
            return ''.join(ss)
        decrypt = encrypt

    class NUL:
        def encrypt(self, data):
            return data
        decrypt = encrypt

    class Crypto:
        _BlockSize = {'AES':16, 'ARC2':8, 'ARC4':1, 'Blowfish':8, 'CAST':8,
                      'DES':8, 'DES3':8, 'IDEA':8, 'RC5':8, 'XOR':1}
        _Modes = ['ECB', 'CBC', 'CFB', 'OFB', 'PGP'] #CTR needs 4 args
        _KeySize = {'AES':[16,24,32], 'CAST':xrange(5,17),
                    'DES':[8], 'DES3':[16,24], 'IDEA':[16]}

        def __init__(self, mode='AES-CBC-32'):
            mode = mode.split('-')
            mode += [''] * (3 - len(mode))
            #check cipher
            self.cipher = mode[0] if mode[0] else 'AES'
            if self.cipher not in self._BlockSize:
                raise ValueError('Invalid cipher: '+self.cipher)
            #check ciphermode
            if self._BlockSize[self.cipher] == 1:
                self.ciphermode = ''
            else:
                self.ciphermode = mode[1] if mode[1] in self._Modes else 'CBC'
            #check keysize
            try:
                self.keysize = int(mode[2])
            except ValueError:
                self.keysize = 32
            if self.keysize != 0:
                if self.cipher in self._KeySize:
                    keysize = self._KeySize[self.cipher]
                    if self.keysize not in keysize:
                        self.keysize = keysize[-1]
            #avoid Memmory Error
            if self.cipher=='RC5' and self.keysize in (1, 57): self.keysize=32
            #try to import Crypto.Cipher.xxxx
            try:
                cipherlib = __import__('Crypto.Cipher.'+self.cipher, fromlist='x')
                self._newobj = cipherlib.new
                if self._BlockSize[self.cipher] != 1:
                    self._ciphermode = getattr(cipherlib, 'MODE_'+self.ciphermode)
            except ImportError:
                if self.cipher == 'XOR': self._newobj = XOR
                else: raise

        def paddata(self, data):
            blocksize = self._BlockSize[self.cipher]
            if blocksize != 1:
                padlen = (blocksize - len(data) - 1) % blocksize
                data = '%s%s%s' % (chr(padlen), ' '*padlen, data)
            return data

        def unpaddata(self, data):
            if self._BlockSize[self.cipher] != 1:
                padlen = ord(data[0])
                data = data[padlen+1:]
            return data

        def getcrypto(self, key):
            if self.keysize==0 and key=='':
                return NUL()
            khash = hashlib.sha512(key).digest()
            if self.keysize != 0:
                key = khash[:self.keysize]
            blocksize = self._BlockSize[self.cipher]
            if blocksize == 1:
                return self._newobj(key)
            return self._newobj(key, self._ciphermode, khash[-blocksize:])

        def encrypt(self, data, key):
            crypto = self.getcrypto(key)
            data = self.paddata(data)
            return crypto.encrypt(data)

        def decrypt(self, data, key):
            crypto = self.getcrypto(key)
            data = crypto.decrypt(data)
            return self.unpaddata(data)

        def getmode(self):
            return '%s-%s-%d' % (self.cipher, self.ciphermode, self.keysize)

        def __str__(self):
            return '%s("%s")' % (self.__class__, self.getmode())

        def getsize(self, size):
            blocksize = self._BlockSize[self.cipher]
            return (size + blocksize - 1) // blocksize * blocksize

    class Crypto2(Crypto):
        def paddata(self, data):
            blocksize = self._BlockSize[self.cipher]
            if blocksize != 1:
                padlen = (blocksize - len(data) - 1) % blocksize
                data = '%s%s%s' % (data, ' '*padlen, chr(padlen))
            return data

        def unpaddata(self, data):
            if self._BlockSize[self.cipher] != 1:
                padlen = ord(data[-1])
                data = data[:-(padlen+1)]
            return data

    # =============================== plugins._base ================================
    HeaderDict, Proxy, URLInfo, del_bad_hosts, start_new_server, unparse_netloc = import_from(utils)
    import time, re, random, threading, socket, os, traceback

    class Handler(object):
        _dirty_headers = ('Connection', 'Proxy-Connection', 'Proxy-Authorization',
                         'Content-Length', 'Host', 'Vary', 'Via', 'X-Forwarded-For')
        _range_re = re.compile(r'(\d+)?-(\d+)?')
        _crange_re = re.compile(r'bytes\s+(\d+)-(\d+)/(\d+)')
        crypto = Crypto('XOR--32'); key = ''
        proxy = global_proxy
        headers = HeaderDict('Content-Type: application/octet-stream')
        range0 = 100000; range = 500000; max_threads = 10

        def __init__(self, config):
            dic = {'crypto': Crypto, 'key': lambda v:v, 'headers': HeaderDict,
                   'proxy': lambda v:global_proxy if v=='default' else Proxy(v),
                   'range0': lambda v:v if v>=10000 else self.__class__.range0,
                   'range': lambda v:v if v>=100000 else self.__class__.range,
                   'max_threads': lambda v:v if v>0 else self.__class__.max_threads,}
            self.url = URLInfo(config['url'])
            for k,v in dic.iteritems():
                if k in config:
                    setattr(self.__class__, k, v(config[k]))
                setattr(self, k, getattr(self.__class__, k))

        def __str__(self):
            return ' %s %s %d %d %d' % (self.url.url, self.crypto.getmode(),
                    self.range0, self.range, self.max_threads)

        def dump_data(self, data):
            raise NotImplementedError

        def load_data(self, data):
            raise NotImplementedError

        def process_request(self, req, force_range):
            data, headers = req.read_body(), req.headers
            for k in self._dirty_headers:
                del headers[k]
            if req.command == 'GET':
                rawrange, range = self._process_range(req.headers)
                if force_range:
                    headers['Range'] = range
            else:
                rawrange, range = '', ''
            request = {'url':req.url, 'method':req.command,
                       'headers':headers, 'payload':data, 'range':range}
            return request, rawrange

        def _process_range(self, headers):
            range = headers.get('Range', '')
            m = self._range_re.search(range)
            if m:
                m = m.groups()
                if m[0] is None:
                    if m[1] is None: m = None
                    else:
                        m = 1, int(m[1])
                        if m[1] > self.range0: range = 'bytes=-1024'
                else:
                    if m[1] is None:
                        m = 0, int(m[0])
                        range = 'bytes=%d-%d' % (m[1], m[1]+self.range0-1)
                    else:
                        m = 2, int(m[0]), int(m[1])
                        if m[2]-m[1]+1 > self.range0:
                            range = 'bytes=%d-%d' % (m[1], m[1]+self.range0-1)
            if m is None:
                range = 'bytes=0-%d' % (self.range0 - 1)
            return m, range

        def _fetch(self, data):
            data = self.crypto.encrypt(data, self.key)
            url = self.url
            opener = self.proxy.get_opener(url)
            try:
                resp = opener.open(url, data, 'POST', self.headers, 0)
            except Exception, e:
                return -1, e
            if resp.status != 200:
                opener.close()
                return -1, '%s: %s' % (resp.status, resp.reason)
            return 0, resp

        def fetch(self, data):
            raise NotImplementedError

        def read_data(self, type, data):
            if type == 1: return data
            resp, crypto = data
            data = self.crypto.unpaddata(crypto.decrypt(resp.read()))
            resp.close()
            return data

        def write_data(self, req, type, data):
            sendall = req.socket.sendall
            if type == 1:
                sendall(data)
            else:
                resp, crypto = data
                size = self.crypto.getsize(16384)
                data = crypto.decrypt(resp.read(size))
                sendall(self.crypto.unpaddata(data))
                data = resp.read(size)
                while data:
                    sendall(crypto.decrypt(data))
                    data = resp.read(size)
                resp.close()

        def _need_range_fetch(self, req, res, range):
            headers = res[2]
            m = self._crange_re.search(headers.get('Content-Range', ''))
            if not m: return None
            m = map(int, m.groups())#bytes %d-%d/%d
            if range is None:
                start=0; end=m[2]-1
                code = 200
                del headers['Content-Range']
            else:
                if range[0] == 0: #bytes=%d-
                    start=range[1]; end=m[2]-1
                elif range[0] == 1: #bytes=-%d
                    start=m[2]-range[1]; end=m[2]-1
                else: #bytes=%d-%d
                    start=range[1]; end=range[2]
                code = 206
                headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end, m[2])
            headers['Content-Length'] = str(end-start+1)
            req.start_response(code, headers)
            if start == m[0]: #Valid
                self.write_data(req, res[0], res[3])
                start = m[1] + 1
            return start, end

        def range_fetch(self, req, handler, request, start, end):
            t = time.time()
            if self._range_fetch(req, handler, request, start, end):
                t = time.time() - t
                t = (end - start + 1) / 1000.0 / t
                print '>>>>>>>>>> Range Fetch ended (all @ %sKB/s)' % t
            else:
                req.close_connection = 1
                print '>>>>>>>>>> Range Fetch failed'

        def _range_fetch(self, req, handler, request, start, end):
            request['range'] = '' # disable server auto-range-fetch
            i, s, thread_size, tasks = 0, start, 10, []
            while s <= end:
                e = s + (i < thread_size and self.range0 or self.range) - 1
                if e > end: e = end
                tasks.append((i, s, e))
                i += 1; s = e + 1
            task_size = len(tasks)
            thread_size = min(task_size, len(handler)*2, self.max_threads)
            print ('>>>>>>>>>> Range Fetch started: threads=%d blocks=%d '
                    'bytes=%d-%d' % (thread_size, task_size, start, end))
            if thread_size == 1:
                return self._single_fetch(req, handler, request, tasks)
            handler = list(handler); random.shuffle(handler)
            if thread_size > len(handler): handler *= 2
            results = [None] * task_size
            mutex = threading.Lock()
            threads = {}
            for i in xrange(thread_size):
                t = threading.Thread(target=handler[i]._range_thread,
                        args=(request, tasks, results, threads, mutex))
                threads[t] = set()
                t.setDaemon(True)
            for t in threads: t.start()
            i = 0; t = False
            while i < task_size:
                if results[i] is not None:
                    try:
                        self.write_data(req, 1, results[i])
                        results[i] = None
                        i += 1
                        continue
                    except:
                        mutex.acquire()
                        del tasks[:]
                        mutex.release()
                        break
                if not threads: #All threads failed
                    if t: break
                    t = True; continue
                time.sleep(1)
            else:
                return True
            return False

        def _single_fetch(self, req, handler, request, tasks):
            try:
                for task in tasks:
                    request['headers']['Range'] = 'bytes=%d-%d' % task[1:]
                    data = self.dump_data(request)
                    for i in xrange(3):
                        self = random.choice(handler)
                        res = self.fetch(data)
                        if res[0] == -1:
                            time.sleep(2)
                        elif res[1] == 206:
                            #print res[2]
                            print '>>>>>>>>>> block=%d bytes=%d-%d' % task
                            self.write_data(req, res[0], res[3])
                            break
                    else:
                        raise StopIteration('Failed')
            except:
                return False
            return True

        def _range_thread(self, request, tasks, results, threads, mutex):
            ct = threading.current_thread()
            while True:
                mutex.acquire()
                try:
                    if threads[ct].intersection(*threads.itervalues()):
                        raise StopIteration('All threads failed')
                    for i,task in enumerate(tasks):
                        if task[0] not in threads[ct]:
                            task = tasks.pop(i)
                            break
                    else:
                        raise StopIteration('No task for me')
                    request['headers']['Range'] = 'bytes=%d-%d' % task[1:]
                    data = self.dump_data(request)
                except StopIteration, e:
                    #print '>>>>>>>>>> %s: %s' % (ct.name, e)
                    del threads[ct]
                    break
                finally:
                    mutex.release()
                success = False
                for i in xrange(2):
                    res = self.fetch(data)
                    if res[0] == -1:
                        time.sleep(2)
                    elif res[1] == 206:
                        try: data = self.read_data(res[0], res[3])
                        except: continue
                        if len(data) == task[2]-task[1]+1:
                            success = True
                            break
                mutex.acquire()
                if success:
                    print '>>>>>>>>>> block=%d bytes=%d-%d'%task, len(data)
                    results[task[0]] = data
                else:
                    threads[ct].add(task[0])
                    tasks.append(task)
                    tasks.sort(key=lambda x: x[0])
                mutex.release()

        def handle(self, handler, req, force_range):
            req.handler_name = handler[0].handler_name
            if len(handler) == 1:
                handlers = handler[0], handler[0]
            else:
                handlers = random.sample(handler, 2)
            request, range = self.process_request(req, force_range)
            data = self.dump_data(request)
            errors = []
            for self in handlers:
                res = self.fetch(data)
                if res[0] != -1: break
                e = res[1]; es = str(e); errors.append(es)
                if not es.startswith('Server: '): del_bad_hosts()
            else:
                return req.send_error(502, str(errors))
            if res[1]==206 and req.command=='GET':
                data = self._need_range_fetch(req, res, range)
                if data:
                    start, end = data
                    if start > end: return #end
                    return self.range_fetch(req, handler, request, start, end)
            req.start_response(res[1], res[2])
            self.write_data(req, res[0], res[3])

    def _base_init(cls, config, listen=None):
        name = cls.handler_name
        print 'Initializing %s for old version.' % name
        server = [None] * len(config)
        for i,v in enumerate(config):
            if isinstance(v, basestring):
                v = {'url': v}
            try:
                server[i] = cls(v)
                print server[i]
            except:
                traceback.print_exc()
        def handler(req, force_range=False):
            return server[0].handle(server, req, force_range)
        if listen:
            def find_handler(req):
                if req.proxy_type.endswith('http'):
                    return handler
            listen = data['%s_server'%name] = start_new_server(listen, find_handler)
            print ' %s listen on: %s' % (name, unparse_netloc(listen.server_address[:2]))
        return handler

    # ============================== plugins.gaeproxy ==============================
    import zlib, struct, cPickle as pickle

    class GAEHandler(Handler):
        handler_name = 'OGAE'
        def dump_data(self, data):
            return zlib.compress(pickle.dumps(data, 1))

        def load_data(self, data):
            return pickle.loads(data)

        def process_request(self, req, force_range):
            data, headers = req.read_body(), req.headers
            for k in self._dirty_headers:
                del headers[k]
            if req.command == 'GET':
                rawrange, range = self._process_range(req.headers)
                if force_range:
                    headers['Range'] = range
            else:
                rawrange, range = '', ''
            request = {'url':req.url, 'method':req.command, 'payload':data,
                       'headers':headers.__getstate__(), 'range':range}
            return request, rawrange

        def fetch(self, data):
            data, resp = self._fetch(data)
            if data == -1: return data, resp
            crypto = self.crypto.getcrypto(self.key)
            headers = HeaderDict()
            try:
                raw_data = resp.read(7)
                zip, code, hlen = struct.unpack('>BHI', raw_data)
                if zip == 1:
                    data = self.crypto.unpaddata(crypto.decrypt(resp.read()))
                    data = zlib.decompress(data)
                    content = data[hlen:]
                    if code == 555:
                        raise ValueError('Server: '+content)
                    headers.__setstate__(self.load_data(data[:hlen]))
                    resp.close()
                    return 1, code, headers, content
                elif zip == 0:
                    h = crypto.decrypt(resp.read(hlen))
                    headers.__setstate__(self.load_data(self.crypto.unpaddata(h)))
                    if code == 555:
                        content = crypto.decrypt(resp.read())
                        raise ValueError('Server: '+self.crypto.unpaddata(content))
                    return 0, code, headers, (resp, crypto)
                else:
                    raw_data += resp.read()
                    raise ValueError('Data format not match(%s:%s)'%(self.url.url, raw_data))
            except Exception, e:
                resp.close()
                return -1, e

    def gaeproxy(*a, **kw):
        return _base_init(GAEHandler, *a, **kw)

    # =============================== plugins.forold ===============================
    class OldHandler(Handler):
        handler_name = 'OOLD'
        crypto = Crypto2('XOR--32')

        _unquote_map = {'0':'\x10', '1':'=', '2':'&'}
        def _quote(self, s):
            return str(s).replace('\x10', '\x100').replace('=','\x101').replace('&','\x102')
        def dump_data(self, dic):
            return zlib.compress('&'.join('%s=%s' % (self._quote(k),
                    self._quote(v)) for k,v in dic.iteritems()))
        def _unquote(self, s):
            res = s.split('\x10')
            for i in xrange(1, len(res)):
                item = res[i]
                try:
                    res[i] = self._unquote_map[item[0]] + item[1:]
                except KeyError:
                    res[i] = '\x10' + item
            return ''.join(res)
        def load_data(self, qs):
            pairs = qs.split('&')
            dic = {}
            for name_value in pairs:
                if not name_value:
                    continue
                nv = name_value.split('=', 1)
                if len(nv) != 2:
                    continue
                if len(nv[1]):
                    dic[self._unquote(nv[0])] = self._unquote(nv[1])
            return dic

        def __init__(self, config):
            if 'crypto' in config:
                self.__class__.crypto = Crypto2(config.pop('crypto'))
            Handler.__init__(self, config)

        def fetch(self, data):
            data, resp = self._fetch(data)
            if data == -1: return data, resp
            try:
                raw_data = resp.read(); resp.close()
                data = self.crypto.decrypt(raw_data, self.key)
                if data[0] == '0':
                    data = data[1:]
                elif data[0] == '1':
                    data = zlib.decompress(data[1:])
                else:
                    return -1, 'Data format not match(%s:%s)' % (self.url.url,raw_data)
                code, hlen, clen = struct.unpack('>3I', data[:12])
                if len(data) != 12+hlen+clen:
                    return -1, 'Data length not match'
                content = data[12+hlen:]
                if code == 555:     #Urlfetch Failed
                    return -1, 'Server: '+content
                headers = HeaderDict(self.load_data(data[12:12+hlen]))
                return 1, code, headers, content
            except Exception, e:
                return -1, e

    def forold(*a, **kw):
        return _base_init(OldHandler, *a, **kw)

    # =============================== plugins.goagent ==============================
    from binascii import a2b_hex, b2a_hex

    class GAHandler(OldHandler):
        handler_name = 'OGA'
        crypto = Crypto('XOR--0'); key = ''
    
        def dump_data(self, dic):
            return zlib.compress('&'.join('%s=%s' % (k,b2a_hex(str(v))) for k,v in dic.iteritems()))
    
        def load_data(self, qs):
            return dict((k,a2b_hex(v)) for k,v in (x.split('=') for x in qs.split('&')))
    
        def __init__(self, config):
            config.pop('crypto', None)
            self.password = config.pop('key', '')
            OldHandler.__init__(self, config)
    
        def process_request(self, req, force_range):
            request, rawrange = OldHandler.process_request(self, req, force_range)
            request['password'] = self.password
            return request, rawrange

    def goagent(*a, **kw):
        return _base_init(GAHandler, *a, **kw)

    # =============================== plugins.simple ===============================
    class SPHandler(GAEHandler):
        handler_name = 'OSP'
        def dump_data(self, dic):
            return zlib.compress('&'.join('%s=%s' % (k,b2a_hex(str(v))) for k,v in dic.iteritems()))

        def load_data(self, qs):
            return dict((k,a2b_hex(v)) for k,v in (x.split('=') for x in qs.split('&'))) if qs else {}

        process_request = Handler.process_request

    def simple(*a, **kw):
        return _base_init(SPHandler, *a, **kw)

    # =============================== plugins.simple2 ==============================
    import marshal

    class SP2Handler(Handler):
        handler_name = 'OSP2'
        def dump_data(self, data):
            return marshal.dumps(tuple((k,str(v)) for k,v in data.iteritems()))

        def load_data(self, data):
            return dict(marshal.loads(data))

        def fetch(self, data):
            data, resp = self._fetch(data)
            if data == -1: return data, resp
            crypto = self.crypto.getcrypto(self.key)
            try:
                raw_data = resp.read(7)
                mix, code, hlen = struct.unpack('>BHI', raw_data)
                if mix == 0:
                    headers = self.crypto.unpaddata(crypto.decrypt(resp.read(hlen)))
                    if code == 555:
                        content = self.crypto.unpaddata(crypto.decrypt(resp.read()))
                        raise ValueError('Server: '+content)
                    headers = HeaderDict(headers)
                    return 0, code, headers, (resp, crypto)
                elif mix == 1:
                    data = self.crypto.unpaddata(crypto.decrypt(resp.read()))
                    content = data[hlen:]
                    if code == 555:
                        raise ValueError('Server: '+content)
                    headers = HeaderDict(data[:hlen])
                    resp.close()
                    return 1, code, headers, content
                else:
                    raw_data += resp.read()
                    raise ValueError('Data format not match(%s:%s)'%(self.url.url, raw_data))
            except Exception, e:
                resp.close()
                return -1, e

    def simple2(*a, **kw):
        return _base_init(SP2Handler, *a, **kw)

    # ==============================================================================
    globals().update(gaeproxy=gaeproxy, forold=forold, 
        goagent=goagent, simple=simple, simple2=simple2)
