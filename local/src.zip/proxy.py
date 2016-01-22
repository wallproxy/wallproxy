# -*- coding: utf-8 -*-
from __future__ import with_statement

__author__ = 'd3d3LmVodXN0QGdtYWlsLmNvbQ=='.decode('base64')
if '__version__' not in globals():
    __version__ = '2.2.6'

def main():
    # imports
    import os as _os
    try:
        if _os.environ.get('DISABLE_GEVENT'):
            raise ImportError('DISABLE_GEVENT')
        import gevent.monkey
        gevent_no_ipv6 = (gevent.version_info[0] < 1)
        gevent_patch_dns = (gevent.version_info >= (0,13,2))
        gevent.monkey.patch_all(dns=gevent_patch_dns)
    except ImportError:
        gevent = None
        gevent_no_ipv6 = gevent_patch_dns = False
    import sys, re, time, socket as _socket, struct, httplib
    import hashlib, random, functools, threading, thread, marshal
    from os import path as ospath
    from select import select as _select, error as select_error
    from types import ModuleType, FunctionType
    from UserDict import IterableUserDict
    from weakref import WeakValueDictionary
    from datetime import datetime, timedelta
    from traceback import print_exc
    from operator import itemgetter
    from itertools import ifilter
    from base64 import b64encode
    from urlparse import urljoin
    from opcode import opmap
    from errno import EINTR
    ssl = crypto = None
    try:
        import ssl
        from OpenSSL import crypto
    except ImportError:
        pass
    from BaseHTTPServer import BaseHTTPRequestHandler
    if gevent:
        from gevent.server import StreamServer
    if not gevent or gevent_no_ipv6:
        from SocketServer import ThreadingMixIn, TCPServer


    #noinspection PyUnusedLocal
    def DEBUG_LEAK(func):
        pass
        # print '>> %s.func_closure:' % func.__name__
        # vars = func.func_closure
        # if vars:
           # for vars in vars: print vars.cell_contents

    def select(*a):
        while 1:
            try:
                return _select(*a)
            except select_error, e:
                if e.args[0] != EINTR:
                    raise

    def patch_socket():
        mod_env = globals()

        # patch for socket.inet_pton, socket.inet_ntop missing
        if not mod_env.get('inet_pton'):
            def inet_pton(af, ip):
                """inet_pton(af, ip) -> packed IP address string"""
                ip = str(ip)
                msg = 'illegal IP address string passed to inet_pton'
                if af == AF_INET:
                    return inet_aton(ip)
                elif af == AF_INET6:
                    ip = ip.split('::')
                    ln = len(ip)
                    if ln == 1:
                        ip = ip[0].split(':')
                        if len(ip) != 8:
                            raise error, msg
                    elif ln == 2:
                        ip[0] = ip[0].split(':') if ip[0] else []
                        ip[1] = ip[1].split(':') if ip[1] else []
                        ln = len(ip[0]) + len(ip[1])
                        if ln >= 8:
                            raise error, msg
                        #noinspection PyTypeChecker
                        ip = ip[0] + ['0000']*(8-ln) + ip[1]
                    else:
                        raise error, msg
                    for i,v in enumerate(ip):
                        ln = len(v)
                        if ln==0 or ln>4:
                            raise error, msg
                        ip[i] = '0'*(4-ln) + v
                    try:
                        return ''.join(ip).decode('hex')
                    except:
                        raise error, msg
                else:
                    raise error, (97, 'Address family not supported by protocol')
            mod_env['inet_pton'] = inet_pton

        if not mod_env.get('inet_ntop'):
            def inet_ntop(af, ip):
                """inet_ntop(af, packed_ip) -> string formatted IP address"""
                ip = str(ip)
                if af == AF_INET:
                    return inet_ntoa(ip)
                elif af == AF_INET6:
                    if len(ip) != 16:
                        raise ValueError, 'invalid length of packed IP address string'
                    ip = ip.encode('hex')
                    lst = [None] * 8
                    for i in xrange(8):
                        lst[i] = ip[i*4:i*4+4].lstrip('0')
                        if not lst[i]: lst[i] = '0'
                    beststart = bestend = -1
                    i = 0
                    while i < 8:
                        if lst[i] == '0':
                            start = i
                            while i<8 and lst[i]=='0': i+=1
                            if i-start > bestend-beststart:
                                beststart = start
                                bestend = i
                        i += 1
                    if beststart!=-1 and bestend-beststart>1:
                        if beststart==0 and bestend>7:
                            return '::'
                        elif beststart==0 or bestend>7:
                            lst[beststart:bestend] = [':']
                        else:
                            lst[beststart:bestend] = ['']
                    #noinspection PyTypeChecker
                    return ':'.join(lst)
                else:
                    raise ValueError, 'unknown address family %s' % af
            mod_env['inet_ntop'] = inet_ntop

        if not mod_env.get('create_connection'):
            mod_env.setdefault('_GLOBAL_DEFAULT_TIMEOUT', object())
            def create_connection(address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
                    source_address=None):
                host, port = address
                err = None
                for res in getaddrinfo(host, port, 0, SOCK_STREAM):
                    af, socktype, proto, _canonname, sa = res
                    sock = None
                    try:
                        sock = socket(af, socktype, proto)
                        if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                            sock.settimeout(timeout)
                        if source_address:
                            sock.bind(source_address)
                        sock.connect(sa)
                        return sock
                    except error, err:
                        sys.exc_clear()
                        if sock is not None:
                            sock.close()
                if err is not None:
                    raise err
                else:
                    raise error('getaddrinfo returns an empty list')
            mod_env['create_connection'] = create_connection

    if not hasattr(threading, 'current_thread'):
        threading.current_thread = threading.currentThread

    def new_module(name, **kw):
        mod = ModuleType(name)
        mod.__builtins__ = __builtins__
        if kw: mod.__dict__.update(kw)
        return mod

    def env_run(func, globals):
        code = func.func_code
        return FunctionType(code, globals, code.co_name,
            func.func_defaults, func.func_closure)()

    DEBUG_LEAK(patch_socket)
    env_run(patch_socket, _socket.__dict__)

    def tob(s, enc='utf-8'):
        return s.encode(enc) if isinstance(s, unicode) else str(s)

    def tou(s, enc='utf-8', err='strict'):
        return s.decode(enc, err) if isinstance(s, str) else unicode(s)

    def echo(data):
        fp = sys.stdout
        return fp.write(tob(data, getattr(fp, 'encoding', None) or 'utf-8'))

    def info(data):
        if config.debuglevel >= 0: echo(data)

    fs_encoding = sys.getfilesystemencoding() or 'utf-8'

    config_py = 'config.py'
    if len(sys.argv) > 1:
        main_dir = sys.argv[1]
        if not ospath.isdir(main_dir):
            if (ospath.isfile(main_dir) or
                ospath.isfile(ospath.join(ospath.dirname(main_dir), 'proxy.ini'))):
                main_dir, config_py = ospath.split(main_dir)
            else:
                echo('FATAL: config file %r does not exist!\n' % main_dir)
                raise SystemExit(-1)
    else:
        main_dir = ospath.dirname(sys.argv[0])
    main_dir = ospath.abspath(tou(main_dir, fs_encoding))
    config_py = ospath.join(main_dir, tou(config_py, fs_encoding))
    misc_dir = ospath.join(main_dir, 'misc') + _os.sep

    runLock = threading.Lock()
    runLocal = threading.local()

    cachefile = ospath.join(misc_dir, 'cache.dat')
    def cache_get(name, default):
        with runLock:
            try:
                with open(cachefile, 'rb') as fp:
                    cache = marshal.load(fp)
                    return cache.get(name, default)
            except:
                return default

    def cache_set(name, value):
        with runLock:
            try:
                with open(cachefile, 'rb') as fp:
                    cache = marshal.load(fp)
                cache[name] = value
            except:
                cache = {name: value}
            try:
                with open(cachefile, 'wb') as fp:
                    marshal.dump(cache, fp)
            except:
                return False
        return True

    def urlsplit(url):
        i = url.find('://')
        if i < 0:
            i = j = 0
        else:
            j = i + 3
        k = url.find('/', j)
        return url[:i].lower(), url[j:None if k<0 else k], '/' if k<0 else url[k:]

    def parse_userloc(netloc):
        username = password = None
        if '@' in netloc:
            username, netloc = netloc.rsplit('@', 1)
            if ':' in username:
                username, password = username.split(':', 1)
        return username, password, netloc

    def parse_netloc(netloc, dport=None):
        port = None
        i = netloc.rfind(':')
        j = netloc.rfind(']')
        if i != -1:
            if (j==-1 and netloc.find(':')==i) or (j!=-1 and i>j):
                try:
                    port = int(netloc[i+1:])
                except ValueError:
                    pass
                netloc = netloc[:i]
        if j != -1:
            netloc = netloc[netloc.find('[')+1:j]
        if port is None:
            port = dport
        return netloc.lower(), port

    def unparse_netloc((hostname, port), dport=None):
        if ':' in hostname:
            hostname = '[' + hostname + ']'
        if port != dport:
            hostname = '%s:%s' % (hostname, port)
        return hostname

    def _parse_http_list(s):
        res = []
        part = ''
        escape = quote = False
        for cur in s:
            if escape:
                escape = False
            elif quote:
                if cur == '\\':
                    escape = True
                    continue
                elif cur == '"':
                    quote = False
            elif cur == '"':
                quote = True
            elif cur == ',':
                res.append(part)
                part = ''
                continue
            part += cur
        if part:
            res.append(part)
        return [part.strip() for part in res]

    def _parse_keqv_list(l):
        parsed = {}
        for elt in l:
            k, _, v = elt.partition('=')
            if not _: continue
            if v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            parsed[k] = v
        return parsed

    def digest_auth(method, auth, realm, (username, password), nonce):
        hash = lambda *a: hashlib.md5(':'.join(a)).hexdigest()
        nonce = hash(username, nonce, password)
        request = ('Digest realm="%s", qop=auth, algorithm=MD5, nonce="%s", '
            'opaque="384db8de9cb0bdb40ead9066298cd3242c31e730"' % (realm, nonce))
        if not auth: return request
        auth = auth.split(None, 1)
        if len(auth) != 2 or auth[0].lower() != 'digest': return request
        auth = _parse_keqv_list(_parse_http_list(auth[1]))
        if (auth.get('username') != username or
            auth.get('realm') != realm or
            auth.get('qop') != 'auth' or
            auth.get('algorithm', '').upper() != 'MD5' or
            auth.get('nonce') != nonce):
            return request
        try:
            HA1 = hash(username, realm, password)
            HA2 = hash(method, auth['uri'])
            resp = hash(HA1, auth['nonce'], auth['nc'],
                auth['cnonce'], auth['qop'], HA2)
            if auth['response'] != resp:
                return request
        except KeyError:
            return request

    def digest_client(method, uri, auth, (username, password)):
        auth = _parse_keqv_list(_parse_http_list(auth))
        _hash = (hashlib.sha1 if auth.get('algorithm', 'MD5').upper()
            == 'SHA' else hashlib.md5)
        hash = lambda *a: _hash(':'.join(a)).hexdigest()
        try:
            HA1 = hash(username, auth['realm'], password)
            HA2 = hash(method, uri)
            qop = auth.get('qop')
            nonce = auth['nonce']
            if qop is None:
                resp = hash(HA1, nonce, HA2)
            else:
                nc = '00000001'
                cnonce = '384db8de9cb0bdb40ead9066298cd3242c31e730'
                resp = hash(HA1, nonce, nc, cnonce, qop, HA2)
            auth['username'] = username
            auth['uri'] = uri
            auth['response'] = resp
            auth = ', '.join(['%s="%s"'%(k,v) for k,v in auth.iteritems()])
            if qop is not None:
                #noinspection PyUnboundLocalVariable
                auth += ', nc=%s, cnonce="%s"' % (nc, cnonce)
            return 'Digest ' + auth
        except KeyError:
            pass

    def find_assign_names():
        code = sys._getframe(2)
        co = code.f_code
        code = co.co_code[code.f_lasti+3:]
        named = {
            opmap['STORE_FAST']: co.co_varnames,
            opmap['STORE_DEREF']: co.co_cellvars + co.co_freevars,
            opmap['STORE_NAME']: co.co_names,
            opmap['STORE_GLOBAL']: co.co_names,
        }
        argv = lambda i: (ord(code[i]) + (ord(code[i+1]) << 8))
        namev = lambda i: named[ord(code[i])][argv(i+1)]
        count, i = ((argv(1), 3) if ord(code[0]) ==
            opmap['UNPACK_SEQUENCE'] else (1, 0))
        return [namev(i) for i in xrange(i, i + 3 * count, 3)]

    class HeaderDict(IterableUserDict):
        def __setitem__(self, key, value):
            self.data[key.title()] = value

        def add(self, key, value):
            data = self.data
            key = key.title()
            prev = data.get(key)
            if prev is None:
                data[key] = value
            else:
                data[key] = '%s\r\n%s: %s' % (prev, key, value)

        def __delitem__(self, key):
            self.data.pop(key, None)

        def __getitem__(self, key):
            return self.data[key]

        def get(self, key, default=None):
            return self.data.get(key, default)

        def readheaders(self, fp):
            for line in fp:
                k, s, v = line.partition(':')
                if not s: break
                self.add(k, v.strip())

        def update(self, dict=None, **kw):
            if not dict:
                pass
            elif hasattr(dict, 'readline'):
                self.readheaders(dict)
            elif isinstance(dict, str):
                self.readheaders(dict.splitlines())
            elif isinstance(dict, HeaderDict):
                self.data.update(dict.data)
            else:
                try:
                    for k in dict.keys():
                        self[k] = dict[k]
                except AttributeError:
                    for k,v in dict:
                        self.add(k, v)
            if kw: self.update(kw)

        def __str__(self):
            return ''.join(['%s: %s\r\n'%kv for kv in self.data.iteritems()])

        def __getstate__(self):
            return self.data

        def __setstate__(self, state):
            self.data = state

    class HTTPMessage(HeaderDict):
        #noinspection PyUnusedLocal
        def __init__(self, fp, seekable=1):
            HeaderDict.__init__(self, fp)

        def __getitem__(self, name):
            return self.data[name.title()]

        def getheader(self, name, default=None):
            return self.data.get(name.title(), default)

        def getheaders(self, name):
            name = name.title()
            try:
                return self.data[name].split('\r\n%s: ' % name)
            except KeyError:
                return []

        # for debuglevel
        @property
        def headers(self):
            return ['%s: %s\r\n'%kv for kv in self.data.iteritems()]

    httplib.HTTPMessage = HTTPMessage

    # Certificate Manager
    def readFile(filename):
        with open(filename, 'rb') as fp:
            return fp.read()

    def writeFile(filename, content):
        with open(filename, 'wb') as fp:
            return fp.write(tob(content))

    def deleteFiles(*files):
        for file in files:
            if ospath.isfile(file):
                _os.remove(file)

    def _createKeyPair(type=None, bits=1024):
        if type is None:
            type = crypto.TYPE_RSA
        pkey = crypto.PKey()
        pkey.generate_key(type, bits)
        return pkey

    def _createCertRequest(pkey, subj, digest='sha1'):
        req = crypto.X509Req()
        subject = req.get_subject()
        for k,v in subj:
            setattr(subject, k, v)
        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    def _createCertificate(req, issuerKey, issuerCert, serial, digest='sha1'):
        isCA = req is issuerCert
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(serial)
        if isCA:
            cert.set_notBefore('20000101000000Z')
            cert.gmtime_adj_notAfter(60*60*24*7305) #20 years
        else:
            cert.set_notBefore(issuerCert.get_notBefore())
            cert.set_notAfter(issuerCert.get_notAfter())
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if isCA: # CA
            X509Extension = crypto.X509Extension
            exts = [
                X509Extension('basicConstraints', True, 'CA:TRUE'),
                X509Extension('keyUsage', True, 'digitalSignature,keyCertSign,cRLSign'),
                X509Extension('extendedKeyUsage', False, 'serverAuth,clientAuth,'
                    'emailProtection,codeSigning,timeStamping,1.3.6.1.4.1.311.10.12.1'),
            ]
            try:
                exts.append(X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert))
            except TypeError:
                cert.add_extensions(exts)
            else:
                cert.add_extensions(exts)
                cert.add_extensions([
                    X509Extension('authorityKeyIdentifier', False, 'keyid:always', issuer=cert),
                ])
        cert.sign(issuerKey, digest)
        return cert

    def _makeCA(dump=True):
        pkey = _createKeyPair(bits=2048)
        subj = (('countryName', 'CN'), ('stateOrProvinceName', 'Internet'),
                ('localityName','ChinaNet'), ('organizationName', 'WallProxy'),
                ('organizationalUnitName', 'WallProxy Root'),
                ('commonName', 'WallProxy CA'))
        req = _createCertRequest(pkey, subj)
        cert = _createCertificate(req, pkey, req, 0)
        if dump:
            pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
            cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        return pkey, cert

    def _makeCert(host, (cakey, cacrt), serial, dump=True):
        pkey = _createKeyPair()
        subj = (('countryName', 'CN'), ('stateOrProvinceName', 'Internet'),
                ('localityName','ChinaNet'), ('organizationName', host),
                ('organizationalUnitName', 'WallProxy Branch'),
                ('commonName', host))
        req = _createCertRequest(pkey, subj)
        cert = _createCertificate(req, cakey, cacrt, serial)
        if dump:
            pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
            cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        return pkey, cert

    certDir = ospath.join(main_dir, 'cert')
    certsDir = ospath.join(certDir, 'certs')
    certDir2 = ospath.join(certDir, 'missing')
    class CertInfo(object):
        CA = None
        caDir = certDir
        certsDir = None

    def _checkCA():
        pathjoin = ospath.join; isfile = ospath.isfile
        CertInfo.certsDir = certsDir
        keyFile = pathjoin(certDir, 'CA.key')
        crtFile = pathjoin(certDir, 'CA.crt')
        if crypto:
            if not ospath.isdir(certsDir):
                deleteFiles(certsDir); _os.makedirs(certsDir)
            #noinspection PyBroadException
            try:
                key = readFile(keyFile); crt = readFile(crtFile)
                key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
                crt = crypto.load_certificate(crypto.FILETYPE_PEM, crt)
                CertInfo.CA = key, crt
            except:
                CertInfo.CA = key, crt = _makeCA(False)
                #Remove old certifications, because ca and cert must be in pair
                deleteFiles(*[pathjoin(certsDir, n) for n in _os.listdir(certsDir)])
                key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
                crt = crypto.dump_certificate(crypto.FILETYPE_PEM, crt)
                writeFile(keyFile, key)
                writeFile(crtFile, crt)
                if _os.name == 'nt':
                    _os.system('cd /d "%s" && certmgr.exe -del -n "WallProxy CA" -c -s -r currentUser Root>nul 2>nul & certmgr.exe -add "%s" -c -s -r currentUser Root>nul 2>nul' %
                        (tob(main_dir, fs_encoding), tob(crtFile, fs_encoding)))
        else:
            if not (isfile(keyFile) and isfile(crtFile)):
                CertInfo.caDir = CertInfo.certsDir = certDir2
                keyFile = pathjoin(certDir2, 'CA.key')
                crtFile = pathjoin(certDir2, 'CA.crt')
                return isfile(keyFile) and isfile(crtFile)
        return True

    def getCertificate(host, wildcard):
        pathjoin = ospath.join; isfile = ospath.isfile
        fname = host.replace(':', '#')
        keyFile = pathjoin(CertInfo.certsDir, fname+'.key')
        crtFile = pathjoin(CertInfo.certsDir, fname+'.crt')
        if not (isfile(keyFile) and isfile(crtFile)):
            if len(host) > 64:
                wildcard = True
            elif wildcard:
                if ':' not in host and host.count('.') >= 2:
                    #noinspection PyBroadException
                    try: _socket.inet_aton(host)
                    except: pass
                    else: wildcard = False
                #verify failed
                else:
                    wildcard = False
            if wildcard:
                host = host.split('.', 1)[-1][-62:]
                host, fname = '*.' + host, '_.' + host
                keyFile = pathjoin(CertInfo.certsDir, fname+'.key')
                crtFile = pathjoin(CertInfo.certsDir, fname+'.crt')
            if not (wildcard and isfile(keyFile) and isfile(crtFile)):
                if crypto:
                    with runLock:
                        if not (isfile(keyFile) and isfile(crtFile)):
                            serial = int(time.time() * 100)
                            key, crt = _makeCert(host, CertInfo.CA, serial)
                            writeFile(keyFile, key)
                            writeFile(crtFile, crt)
                else:
                    keyFile = pathjoin(CertInfo.caDir, 'CA.key')
                    crtFile = pathjoin(CertInfo.caDir, 'CA.crt')
        return keyFile, crtFile

    def _certFormatTime(t):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
            time.mktime(time.strptime(t, '%Y%m%d%H%M%SZ')) - time.timezone))

    def initCertMgr():
        _initCertMgr()
        if CertInfo.caDir:
            CertInfo.caDir = tob(CertInfo.caDir, fs_encoding)
        if CertInfo.certsDir:
            CertInfo.certsDir = tob(CertInfo.certsDir, fs_encoding)

    def _initCertMgr():
        echo('Initializing fake CA for https2http:\n')
        if not ospath.isdir(misc_dir):
            deleteFiles(misc_dir); _os.makedirs(misc_dir)
        if not ssl:
            return echo('  Aborted: You have no ssl module, https2http is not '
                'supported. Please install from http://pypi.python.org/pypi/ssl/ '
                'or use Python 2.6/2.7 (recommended).\n')
        conf = config.config
        config.cert_wildcard = not crypto or bool(conf.get('cert_wildcard', True))
        if not _checkCA():
            return echo('  Error: You have no OpenSSL module, and CA.key or '
                'CA.crt is missing from "%s" and "%s", https2http is not '
                'supported. Please switch to a Python environment with OpenSSL '
                'support.\n' % (certDir, certDir2))
        elif not crypto:
            echo("  Warning: You have no OpenSSL module, https2http is "
                "partially supported. It's strongly recommended to switch "
                "to a Python environment with OpenSSL support.\n")
        echo('  Please make sure you have imported "%s" to the Trusted root CA '
             'list for your browser.\n' % ospath.join(CertInfo.caDir, 'CA.crt'))
        if CertInfo.CA:
            crt = CertInfo.CA[1]
            echo('  CA Information: %s (%s - %s)\n' % (crt.get_subject().CN,
                 _certFormatTime(crt.get_notBefore()),
                 _certFormatTime(crt.get_notAfter())))
        echo('  Wildcard Certificate: %s\n' % (
                'YES' if config.cert_wildcard else 'NO'))
        cert_prepare = crypto and conf.get('cert_prepare', False)
        if crypto and cert_prepare:
            # for host in ('127.0.0.1', '::1', 'localhost', 'wallproxy',
                # '.google.com', '.google.com.hk', '.googleusercontent.com',
                # '.googleapis.com', '.android.com', '.appspot.com', '.ggpht.com',
                # '.youtube.com', '.gstatic.com', '.ytimg.com', '.cloudfront.net',
                # 'twitter.com', '.twitter.com', '.twimg.com', '.s3.amazonaws.com',
                # '.facebook.com', '.channel.facebook.com', '.ak.facebook.com',
                # '.ak.fbcdn.net', '.e.akamai.net', '.akamaihd.net'):
                # getCertificate(host, True)
            if hasattr(cert_prepare, '__iter__'):
                for host in cert_prepare:
                    getCertificate(host, True)


    def WebHandler():
        import posixpath
        from zipfile import ZipFile
        from urllib import unquote
        from mimetypes import types_map

        env = config.__dict__
        web_authlocal = env.pop('web_authlocal')
        web_userid = env.pop('web_userid')
        web_register = env.pop('web_register', [])

        class WebHeader(HeaderDict):
            def __setitem__(self, key, value):
                HeaderDict.__setitem__(self, tob(key), tob(value))

            def add(self, key, value):
                HeaderDict.add(self, tob(key), tob(value))

        class HTTPError(Exception):
            def __init__(self, web, code, headers=None, data=''):
                web.code = code
                if headers:
                    web.headers.update(headers)
                self.data = data
                Exception.__init__(self, code)

        class WebHandler(object):
            handlers = []
            errors = {}
            code = 200
            encoding = 'utf-8'

            def setup(self, request):
                self.headers = WebHeader()
                self.request = request
                self.protocol = request.scheme
                self.method = request.command.upper()
                self.home = urljoin(request.url, '/').rstrip('/')
                path = '/' + request.path.lstrip('/')
                i = path.find('?')
                if i < 0:
                    self.query = ''
                else:
                    path, self.query = path[:i], path[i+1:]
                self.path = unquote(path)
                self.inheaders = request.headers
                if request.content_length > 1 * 1024 * 1024:
                    raise HTTPError(self, 413)
                self.body = request.read_body()

            def check_auth(self):
                client_address = self.request.client_address[0]
                if web_authlocal or (self.request.server_address[0] !=
                    client_address):
                    request = digest_auth(self.method,
                        self.inheaders.get('Authorization'),
                        'wallproxy Web Authenticate', web_userid, client_address)
                    if request:
                        self.headers['WWW-Authenticate'] = request
                        raise HTTPError(self, 401)

            def redirect(self, url):
                url = urljoin(self.path, url)
                if url.startswith('/'): url = self.home + url
                raise HTTPError(self, 303 if self.body else 302, {'Location': url})

            def find_handler(self):
                url = self.request.url; path = self.path; method = self.method
                for pat,methods,handler in self.handlers:
                    sub = isinstance(handler, list)
                    args = pat.match(url if sub else path)
                    if args:
                        if '*' not in methods:
                            if method == 'HEAD' and 'HEAD' not in methods:
                                method = 'GET'
                            if method not in methods:
                                raise HTTPError(self, 405, {'Allow': ', '.join(methods)})
                        if sub:
                            home = self.home
                            handlers = self.handlers
                            self.home = args.group(1)
                            self.path = path[len(self.home) - len(home):]
                            self.handlers = handler
                            try:
                                return self.find_handler()
                            finally:
                                self.handlers = handlers
                                self.path = path
                                self.home = home
                        return handler, args.groups()
                raise HTTPError(self, 404)

            def handle(self):
                try:
                    handler, args = self.find_handler()
                    return handler(self, *args)
                except (HTTPError, KeyboardInterrupt, SystemExit):
                    raise
                except:
                    print_exc()
                    raise HTTPError(self, 500)

            def __call__(self, request, start_response):
                try:
                    self.setup(request)
                    response = self.handle()
                except HTTPError, e:
                    handler = self.errors.get(self.code)
                    response = handler(self) if handler else e.data
                headers = self.headers
                ctype = headers.get('Content-Type')
                if not ctype:
                    headers['Content-Type'] = 'text/html; charset=%s' % self.encoding
                elif 'charset=' in ctype:
                    self.encoding = (ctype.rsplit('charset=', 1)
                        [-1].split(';', 1)[0].strip())
                isIter = hasattr(response, 'next')
                if isIter and not headers.get('Content-Length'):
                    isIter = False
                    response = ''.join(response)
                if not isIter:
                    response = tob(response, self.encoding)
                    headers['Content-Length'] = len(response)
                if self.method == 'HEAD':
                    response = ''
                start_response(self.code, headers)
                return response if isIter else [response]

        _methods = {}
        class WebRegister(object):
            def __init__(self, handlers):
                self.handlers = handlers
            def __call__(self, regexp, methods=('GET',)):
                methods = frozenset(methods)
                methods = _methods.setdefault(methods, methods)
                def deco(func):
                    self.handlers.append((re.compile(regexp + '$'), methods, func))
                    return self.__class__(func) if isinstance(func, list) else func
                return deco
        web_handler = WebRegister(WebHandler.handlers)

        def web_error(*codes):
            def deco(func):
                errors = WebHandler.errors
                for code in codes:
                    errors[code] = func
                return func
            return deco

        def coroutine(func):
            def wrapper(*a, **kw):
                co = func(*a, **kw)
                co.next()
                return co
            return wrapper

        types_map = types_map.copy()
        types_map.update({
            '.ico': 'image/x-icon',
            '.pac': 'application/x-ns-proxy-autoconfig',
        })
        def guess_type(path):
            base, ext = ospath.splitext(path)
            return types_map.get(ext.lower(), 'application/octet-stream')

        def httpdate(date):
            return date.strftime('%a, %d %b %Y %H:%M:%S GMT')

        def parsehttpdate(string):
            try:
                return datetime.strptime(string, '%a, %d %b %Y %H:%M:%S %Z')
            except ValueError:
                return None

        def send_static_header(web, path, mtime, max_age, length=None):
            mtime = datetime.utcfromtimestamp(mtime)
            ask_mtime = web.inheaders.get('If-Modified-Since')
            if ask_mtime and parsehttpdate(ask_mtime) == mtime:
                raise HTTPError(web, 304) #304 Not Modified
            headers = web.headers
            headers['Content-Type'] = guess_type(path)
            headers['Last-Modified'] = httpdate(mtime)
            #noinspection PySimplifyBooleanCheck
            if max_age:
                mtime = datetime.utcnow() + timedelta(seconds=max_age)
                headers['Cache-Control'] = 'max-age=%d'%max_age
                headers['Expires'] = httpdate(mtime)
            elif max_age == 0:
                headers['Cache-Control'] = 'no-cache'
            if length is not None:
                headers['Content-Length'] = length

        @coroutine
        def send_static_file(web, root, path, max_age=None):
            path = ospath.abspath(ospath.join(root, path))
            if not (path.startswith(root) and ospath.isfile(path)):
                raise HTTPError(web, 404)
            info = _os.stat(path)
            send_static_header(web, path, info.st_mtime, max_age, info.st_size)
            yield
            with open(path, 'rb') as fp:
                buf = fp.read(8192)
                while buf:
                    yield buf
                    buf = fp.read(8192)

        web_zip = None
        if globals().get('__loader__'):
            web_zip = ZipFile(__loader__.archive)
            try:
                web_zip.getinfo('web/')
                web_root = 'web/'
            except KeyError:
                web_zip.close()
                web_zip = None
                web_root = ospath.abspath(ospath.join(
                    ospath.dirname(__loader__.archive), 'web')) + _os.sep
        else:
            web_root = ospath.abspath(ospath.join(
                ospath.dirname(__file__), 'web')) + _os.sep
        web_root = tou(web_root, fs_encoding)

        if web_zip:
            def send_web_file(web, path, max_age=None):
                path = tob(posixpath.normpath(posixpath.join(web_root, path)))
                try:
                    file = web_zip.getinfo(path)
                except KeyError:
                    raise HTTPError(web, 404)
                mtime = time.mktime(file.date_time + (0, 0, 0))
                send_static_header(web, path, mtime, max_age, file.file_size)
                return web_zip.read(path)
        else:
            def send_web_file(web, path, max_age=None):
                return send_static_file(web, web_root, path, max_age)

        for regfunc in web_register:
            #noinspection PyBroadException
            try:
                regfunc(WebHeader=WebHeader, HTTPError=HTTPError, WebHandler=WebHandler,
                    web_handler=web_handler, web_error=web_error, main_dir=main_dir,
                    send_static_file=send_static_file, send_web_file=send_web_file)
            except:
                print_exc()

        #noinspection PyUnusedLocal
        @web_handler('/(|favicon\.ico|(?:js|css|images|static)/.+)')
        def handler(web, path):
            if not path:
                web.check_auth()
                path = 'index.html'
            elif path.endswith('/'):
                path += 'index.html'
            return send_web_file(web, tou(path))
        static_handler = handler

        #noinspection PyUnusedLocal
        @web_error(401, 404, 500)
        def handler(web):
            code = web.code
            try:
                return send_web_file(web, 'page%d.html' % code)
            except HTTPError:
                if web.code == 304: return ''
                web.code = code
                return web.request.format_error(code)

        #noinspection PyUnusedLocal
        @web_handler('(?i)/ca\.crt')
        def handler(web):
            return send_static_file(web, CertInfo.caDir, 'CA.crt')

        #noinspection PyUnusedLocal
        @web_handler('/(.+\.pac)')
        def handler(web, path):
            data = ''.join(send_static_file(web, misc_dir, path))
            listen = "listen=['%s',%d]" % web.request.server_address
            return data.replace("listen=''", listen, 1)

        def handle_ini(web, dir, file):
            if web.method == 'GET':
                return send_static_file(web, dir, file, 0)
            try:
                with open(ospath.join(dir, file), 'wb') as fp:
                    fp.write(web.body)
            except IOError, e:
                return e
            return 'OK'

        #noinspection PyUnusedLocal
        @web_handler('/(proxy\.ini|user\.ini|config\.py)', ['GET','POST'])
        def handler(web, file):
            web.check_auth()
            return handle_ini(web, main_dir, file)

        #noinspection PyUnusedLocal
        @web_handler('/ini/([\w-]+\.ini)', ['GET','POST'])
        def handler(web, file):
            web.check_auth()
            return handle_ini(web, misc_dir, file)

        #noinspection PyUnusedLocal
        @web_handler('/restart')
        def handler(web):
            web.check_auth()
            web.request.close_connection = True
            servers[0].stop()
            return 'Restarting...'

        #noinspection PyUnusedLocal
        @web_handler('/hosts')
        def handler(web):
            web.check_auth()
            from pprint import pformat
            return '<pre>%s</pre>' % pformat(ConnectionManager[3]())

        #noinspection PyUnusedLocal
        @web_handler('/stat\.js')
        def handler(web):
            web.check_auth()
            web.headers['Content-Type'] = 'application/javascript'
            ini = (i for i in _os.listdir(tob(misc_dir, fs_encoding)) if i.endswith('.ini'))
            return 'var WP = {version:%r, ini:%r};' % (__version__, sorted(ini))

        @web_handler('/certs\.js')
        def handler(web):
            web.headers['Content-Type'] = 'application/javascript'
            certs = (i for i in _os.listdir(CertInfo.certsDir) if i.endswith('.crt'))
            return 'var WP_certs = %r;' % sorted(certs)

        @web_handler('/certs/([#\.\w-]+?\.crt)')
        def handler(web, file):
            return send_static_file(web, CertInfo.certsDir, file)

        web_handler('/(.+)')(static_handler)

        return WebHandler


    default_ports = {'http':80, 'https':443, 'ftp':21, 'socks4':1080, 'socks5':1080}

    class _LazyAttributeDesc(object):
        def __init__(self, func):
            self.name = find_assign_names()[0]
            self.func = func
        #noinspection PyUnusedLocal
        def __get__(self, obj, tp):
            with runLock:
                tp = tp.__dict__
                result = tp[self.name]
                if result is self:
                    result = tp[self.name] = self.func()
                return result

    class ProxyHandler(BaseHTTPRequestHandler):
        WebHandlerCls = _LazyAttributeDesc(WebHandler)
        MessageClass = HTTPMessage
        protocol_version = 'HTTP/1.1'
        proxy_style = False
        proxy_type = ''
        proxy_host = None
        handler_name = 'WP'
        #noinspection PySetFunctionToLiteral
        socks2https = set([443])
        socks2http = set([80])
        #noinspection PySetFunctionToLiteral
        server_addresses = set([('wallproxy', 80), ('wallproxy', 443)])

        #noinspection PyMissingConstructor
        def __init__(self, sock, address, server):
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, True)
            self.socket = sock
            self.client_address = address[:2]
            self.server_address = sock.getsockname()[:2]
            self.server_addresses.add(self.server_address)
            self.server = server

        def parse_request(self):
            if not BaseHTTPRequestHandler.parse_request(self):
                return False
            conn = self.headers.get('Proxy-Connection', '').lower()
            if conn:
                self.proxy_style = True
                if 'close' in conn:
                    self.close_connection = True
                elif 'keep-alive' in conn:
                    self.close_connection = False
            else:
                self.proxy_style = False
            return True

        def send_response(self, code, message=None):
            if code != 400:
                self.log_request(code)
            else:
                host = self.proxy_host
                self.log_error('Bad %s%s: "%s"', self.proxy_type or 'http',
                    (' for ' + unparse_netloc(host)) if host
                    else '', self.requestline[:50].encode('string-escape'))
                if self.proxy_type.startswith('fake'):
                    if self.proxy_type == 'fake_https':
                        target = self.socks2http
                        if host[1] in target: target = self.socks2https
                    else:
                        target = self.socks2https
                        if host[1] in target: target = self.socks2http
                    try:
                        target.remove(host)
                    except KeyError:
                        target.add(host)
            if self.request_version != 'HTTP/0.9':
                if not message:
                    message = self.responses.get(code, ('',))[0]
                self.socket.sendall('HTTP/1.0 %d %s\r\n' % (code, message))

        def start_response(self, code, headers, message=None):
            size = headers.get('Content-Length', '-')
            self.log_request(code, size)
            if size == '-' or code in (413, 414) or self.content_length > 0:
                self.close_connection = True
            if self.request_version != 'HTTP/0.9':
                if not message:
                    message = self.responses.get(code, ('',))[0]
                if headers.get('Transfer-Encoding', '').lower() == 'chunked':
                    del headers['Transfer-Encoding']
                todel, toset = (('Connection', 'Proxy-Connection')
                    if self.proxy_style else ('Proxy-Connection', 'Connection'))
                del headers[todel]
                headers[toset] = 'close' if self.close_connection else 'keep-alive'
                self.socket.sendall('HTTP/1.0 %d %s\r\n%s\r\n' % (
                    code, message, headers))
            self.content_length = None

        def format_error(self, code, message=None):
            reason, explain = self.responses.get(code, ('',''))
            return self.error_message_format % {'code': code,
                'message': (message or reason).replace('&', '&amp;').replace(
                    '<', '&lt;').replace('>', '&gt;'), 'explain': explain}

        #noinspection PyMethodOverriding
        def send_error(self, code, message=None, headers=None):
            if (message != '' and self.proxy_type.endswith('http') and
                self.command != 'HEAD' and code >= 200 and code not in (204, 304)):
                message = self.format_error(code, message)
            else:
                message = ''
            if headers is None:
                headers = ''; self.close_connection = True
            message = ('%s: %s\r\nContent-Type: text/html\r\n'
                'Content-Length: %d\r\n%s\r\n%s' % (
                'Proxy-Connection' if self.proxy_style else 'Connection',
                'close' if self.close_connection else 'keep-alive',
                len(message), headers, message))
            self.send_response(code)
            self.socket.sendall(message)

        def log_message(self, format, *args):
            ip = get_current_ip() if config.debuglevel >= 0 else None
            ip = ' %s'%ip if ip else ''
            sys.stderr.write('%s - [%s] %s%s %s\n' % (self.client_address[0],
                datetime.now().replace(microsecond=0), self.handler_name, ip, format%args))

        def end_socks(self, data, ok=False):
            log, msg = (self.log_message, 'Accept'
                ) if ok else (self.log_error, 'Deny')
            if self.proxy_host:
                log('%s %s for %s', msg, self.proxy_type,
                    unparse_netloc(self.proxy_host))
            else:
                log('%s %s', msg, self.proxy_type)
            self.socket.sendall(data)

        def handle(self):
            try:
                sock = self.socket.recv(1)
                if sock == '\x04': # socks4
                    sock = self.handle_socks4_request()
                elif sock == '\x05': # socks5
                    sock = self.handle_socks5_request()
                if sock is None: return
                self.rfile = self.socket.makefile('rb', -1)
                self.raw_requestline = sock + self.rfile.readline()
                while self.parse_request():
                    del self.raw_requestline
                    self.handler_name = 'WP'
                    if self.command == 'CONNECT': # https
                        self.handle_https_request()
                    else: # http
                        self.handle_http_request()
                    if self.close_connection:
                        break
                    self.raw_requestline = self.rfile.readline()
            except _socket.error:
                pass
            finally:
                #noinspection PyMethodFirstArgAssignment
                self = self.__dict__
                self.pop('rfile', None)
                sock = self.pop('socket', None)
                if sock:
                    try:
                        sock._sock.close() # do not rely on garbage collection
                        sock.close()
                    except _socket.error:
                        pass

        def handle_socks4_request(self):
            self.proxy_type = 'socks4'
            recv = self.socket.recv
            buf = recv(8)
            self.command, port, ip = struct.unpack('>BHI', buf[:7])
            buf, lst = buf[7], []
            while buf != '\x00':
                lst.append(buf)
                buf = recv(1)
            self.userid = ''.join(lst)
            if 0 < ip < 256:
                buf, lst = recv(1), []
                while buf != '\x00':
                    lst.append(buf)
                    buf = recv(1)
                ip = ''.join(lst)
            else:
                ip = _socket.inet_ntoa(struct.pack('>I', ip))
            self.proxy_host = ip, port
            handler = self.server.find_handler(self)
            #noinspection PySimplifyBooleanCheck
            if handler == False:
                # request failed because client's identd could not
                # confirm the user ID string in the request
                return self.end_socks('\x00\x5d\x00\x00\x00\x00\x00\x00')
            elif not handler or self.proxy_host in self.server_addresses:
                return self.fake_socks4()
            del recv, buf, port, ip, lst
            return handler(self)

        def fake_socks4(self):
            self.proxy_type = 'fake_socks4'
            ip, port = self.proxy_host
            try:
                ip = _socket.inet_aton(ip)
            except _socket.error:
                ip = _socket.inet_aton(self.server_address[0])
            # request granted
            self.end_socks('\x00\x5a' + struct.pack('>H', port) + ip, True)
            return self.try_socks2https()

        def handle_socks5_request(self):
            self.proxy_type = 'socks5'
            sendall = self.socket.sendall; recv = self.socket.recv
            buf = recv(ord(recv(1)))
            if '\x02' in buf:
                sendall('\x05\x02') # username/password authentication
                buf = recv(2)
                buf = recv(ord(buf[1])+1)
                self.userid = buf[:-1], recv(ord(buf[-1]))
                sendall('\x01\x00') # success
            elif '\x00' in buf:
                self.userid = None
                sendall('\x05\x00') # no authentication
            else:
                # no acceptable methods
                return self.end_socks('\x05\xff')
            buf = recv(4)
            self.command = ord(buf[1])
            if buf[3] == '\x01': #IPv4 address
                ip = _socket.inet_ntoa(recv(4))
            elif buf[3] == '\x03': #Domain name
                ip = recv(ord(recv(1)))
            elif buf[3] == '\x04': #IPv6 address
                ip = _socket.inet_ntop(_socket.AF_INET6, recv(16))
            else:
                # address type not supported
                return self.end_socks('\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            port = struct.unpack('>H', recv(2))[0]
            self.proxy_host = ip, port
            handler = self.server.find_handler(self)
            #noinspection PySimplifyBooleanCheck
            if handler == False:
                # connection not allowed by ruleset
                return self.end_socks('\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
            elif not handler or self.proxy_host in self.server_addresses:
                return self.fake_socks5()
            del sendall, recv, buf, ip, port
            return handler(self)

        def fake_socks5(self):
            self.proxy_type = 'fake_socks5'
            ip, port = self.proxy_host
            if ':' in ip:
                try:
                    ip = '\x04' + _socket.inet_pton(_socket.AF_INET6, ip)
                except _socket.error:
                    # host unreachable
                    return self.end_socks(
                        '\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
            else:
                try:
                    ip = '\x01' + _socket.inet_aton(ip) #IPv4
                except _socket.error:
                    ip = '\x03' + chr(len(ip)) + ip #domain
            # request granted
            self.end_socks('\x05\x00\x00' + ip + struct.pack('>H', port), True)
            return self.try_socks2https()

        def handle_https_request(self):
            oldcc = self.close_connection
            self.close_connection = True
            proxy_type = self.proxy_type
            if not proxy_type:
                self.proxy_type = proxy_type = 'https'
            elif proxy_type != 'https':
                # CONNECT not allowed in http/https2http mode
                return self.send_error(400, None, '')
            self.userid = self.headers.get('Proxy-Authorization')
            if self.userid is not None:
                del self.headers['Proxy-Authorization']
            self.proxy_host = parse_netloc(self.path, 443)
            if self.proxy_host in self.server_addresses:
                return self.fake_https()
            handler = self.server.find_handler(self)
            #noinspection PySimplifyBooleanCheck
            if handler == False:
                return self.send_error(403, None, '')
            elif not handler:
                return self.fake_https()
            elif isinstance(handler, basestring):
                self.close_connection = oldcc
                return self.send_error(407, None,
                    'Proxy-Authenticate: %s\r\n' % handler)
            del oldcc, proxy_type
            return handler(self)

        def fake_https(self):
            self.proxy_type = 'fake_https'
            host = self.proxy_host; target = self.socks2http
            if (host in target or
                host[1] in target and host not in self.socks2https):
                self.socket.sendall('HTTP/1.0 200 OK\r\n\r\n')
                self.close_connection = False
                return
            return self.try_https2http()

        if ssl:
            def try_socks2https(self):
                host = self.proxy_host; target = self.socks2https
                if (host in target or
                    host[1] in target and host not in self.socks2http):
                    keyfile, crtfile = getCertificate(host[0], config.cert_wildcard)
                    try:
                        self.socket = ssl.wrap_socket(
                            self.socket, keyfile, crtfile, True)
                    except ssl.SSLError, e:
                        if host in target:
                            target.discard(host)
                        else:
                            self.socks2http.add(host)
                        return self.log_error('SSLError for %s: %s',
                            unparse_netloc(host), e)
                    self.proxy_type = 'https2http'
                return ''

            def try_https2http(self):
                host = self.proxy_host
                keyfile, crtfile = getCertificate(host[0], config.cert_wildcard)
                self.socket.sendall('HTTP/1.0 200 OK\r\n\r\n')
                try:
                    sock = ssl.wrap_socket(self.socket, keyfile, crtfile, True)
                except ssl.SSLError, e:
                    if host in self.socks2https:
                        self.socks2https.discard(host)
                    else:
                        self.socks2http.add(host)
                    return self.log_error('SSLError for %s: %s',
                        unparse_netloc(host), e)
                self.socket = sock
                self.rfile = sock.makefile('rb', -1)
                self.close_connection = False
                self.proxy_type = 'https2http'
        else:
            def try_socks2https(self):
                return ''

            def try_https2http(self):
                self.log_error('You have no ssl module support')
                return self.send_error(501)

        def handle_http_request(self):
            proxy_type = self.proxy_type
            headers = self.headers
            if not proxy_type:
                self.proxy_type = proxy_type = 'http'
            elif proxy_type.startswith('fake'):
                self.proxy_type = proxy_type = 'socks2http'
            if proxy_type == 'http':
                self.userid = headers.get('Proxy-Authorization')
                if self.userid is not None:
                    del headers['Proxy-Authorization']
            if self.path.startswith('/'):
                host = headers.get('Host')
                if proxy_type == 'https2http': # https
                    if self.proxy_host not in self.server_addresses and host:
                        self.proxy_host = parse_netloc(host, 443)
                    self.url = ''.join(('https://',
                        unparse_netloc(self.proxy_host, 443), self.path))
                    self.scheme = 'https'
                else:
                    self.proxy_host = (parse_netloc(host, 80)
                        if host else self.server_address)
                    self.url = ''.join(('http://',
                        unparse_netloc(self.proxy_host, 80), self.path))
                    self.scheme = 'http'
                self.requestline = ' '.join((
                    self.command, self.url, self.request_version))
            else:
                self.url = self.path
                self.scheme, host, self.path = urlsplit(self.url)
                self.proxy_host = parse_netloc(host, default_ports.get(self.scheme))
            try:
                self.content_length = int(headers.get('Content-Length', 0))
            except ValueError:
                self.content_length = 0
            del proxy_type, headers, host
            if self.proxy_host in self.server_addresses:
                return self.http_to_web()
            handler = self.server.find_handler(self)
            #noinspection PySimplifyBooleanCheck
            if handler == False:
                return self.send_error(403, None, '')
            elif not handler:
                return self.http_to_web()
            elif isinstance(handler, basestring):
                return self.send_error(407, None,
                    'Proxy-Authenticate: %s\r\n' % handler)
            return handler(self)

        def read_body(self):
            length = self.content_length
            if length > 0:
                self.content_length = 0
                return self.rfile.read(length)
            return ''

        #noinspection PyUnusedLocal
        def copy_sock(self, sock, max_idle=120):
            socks = [self.socket, sock]
            count = 0
            while count < max_idle:
                count += 1
                r, w, e = select(socks, [], socks, 1)
                if e:
                    break
                if r:
                    for sock in r:
                        w = socks[0]
                        if w is sock:
                            w = socks[1]
                        data = sock.recv(8192)
                        if data:
                            w.sendall(data)
                            count = 0

        def http_to_web(self):
            self.handler_name = 'WEB'
            try:
                #noinspection PyCallingNonCallable
                data = self.WebHandlerCls()(self, self.start_response)
            except Exception, e:
                print_exc()
                if self.content_length is None:
                    self.close_connection = True
                else:
                    self.send_error(500, str(e))
            else:
                for data in data:
                    self.socket.sendall(data)

    #noinspection PyUnusedLocal
    def find_proxy_handler(self, req):
        return config.find_proxy_handler(req)

    if gevent:
        class ProxyServer(StreamServer):
            find_handler = find_proxy_handler
            reuse_addr = 1
            def __init__(self, server_address, RequestHandlerClass):
                StreamServer.__init__(self, server_address)
                self.RequestHandlerClass = RequestHandlerClass
                if gevent_no_ipv6:
                    self.pre_start()
                else:
                    self.init_socket()

            @property
            def server_address(self):
                return self.address

            def handle(self, sock, address):
                self.RequestHandlerClass(sock, address, self).handle()

    if not gevent or gevent_no_ipv6:
        if gevent_no_ipv6:
            #noinspection PyUnboundLocalVariable
            _ProxyServer4 = ProxyServer

        class ProxyServer(ThreadingMixIn, TCPServer):
            find_handler = find_proxy_handler
            daemon_threads = True
            allow_reuse_address = True

            def __init__(self, server_address, RequestHandlerClass):
                if ':' in server_address[0]:
                    self.address_family = _socket.AF_INET6
                TCPServer.__init__(self, server_address, RequestHandlerClass)

            def finish_request(self, sock, address):
                self.RequestHandlerClass(sock, address, self).handle()

            if hasattr(TCPServer, 'shutdown'):
                stop = TCPServer.shutdown
            else:
                def serve_forever(self, poll_interval=0.5):
                    self._shutdown_request = False
                    sock = self.socket
                    while not self._shutdown_request:
                        r, w, e = select([sock], [], [], poll_interval)
                        if sock in r:
                            self.handle_request()

                def stop(self):
                    self._shutdown_request = True

        if gevent_no_ipv6:
            _ProxyServer6 = ProxyServer
            def ProxyServer(server_address, RequestHandlerClass):
                if ':' in server_address[0]:
                    return _ProxyServer6(server_address, RequestHandlerClass)
                return _ProxyServer4(server_address, RequestHandlerClass)

    # config module
    config = new_module(__name__+'.config', __file__=config_py)

    def _vget(self, type, name, default):
        #noinspection PyBroadException
        try:
            value = type(self[name])
        except:
            value = type(default)
        return value

    class Config(dict):
        vget = _vget
        def aget(self, type, name, default, *allow):
            value = self.get(name, default)
            if value not in allow:
                #noinspection PyBroadException
                try:
                    value = type(value)
                except:
                    value = type(default)
            return value

    def check_config(env, ifile, ofile, mtime):
        try:
            mtime = (int(_os.stat(ifile).st_mtime) != mtime)
        except OSError:
            return echo('!! Access ini file "%s" failed.\n' % ifile)
        if mtime:
            modules = sys.modules.copy()
            try:
                from make_config import make_config
                code = make_config(ifile, ofile)[0]
            finally:
                sys.modules.clear()
                sys.modules.update(modules)
            try:
                with open(ofile, 'wb') as fp: fp.write(code)
            except IOError:
                echo('!! Save config file %r failed.\n' % ofile)
            env.clear()
            env['__file__'] = ofile
            exec code in env

    def get_config():
        fn = config.__file__; efn = tob(fn, fs_encoding)
        ifile = ospath.join(main_dir, 'proxy.ini')
        mod = ModuleType(config.__name__)
        env = mod.__dict__
        #noinspection PyBroadException
        try:
            #noinspection PyBroadException
            try:
                env['__file__'] = efn
                execfile(efn, env)
            except IOError:
                echo('!! Open config file "%s" failed, try "%s".\n' % (fn, ifile))
                check_config(env, ifile, efn, None)
            except:
                if _vget(env, int, 'ini_config', 0):
                    check_config(env, ifile, efn, None)
                else:
                    raise
            else:
                mtime = _vget(env, int, 'ini_config', 0)
                if mtime:
                    check_config(env, ifile, efn, mtime)
        except:
            print_exc()
        setup = env.pop('config', None)
        if not callable(setup):
            setup = lambda:(lambda self:None)
            echo('!! Warning: You forgot to define a `config()` function in '
                 '"%s".\n' % fn)
        config.config = Config(env)
        return setup

    def setup_config(setup, test=False):
        env = config.__dict__
        conf = config.config
        handlers.setup()
        tasks = []
        def add_task(func, delay=conf.vget(float, 'tasks_delay', 0)):
            tasks.append((delay, func))
        env['add_task'] = add_task
        config.web_register = []; config.server_stop = []
        #noinspection PyBroadException
        try:
            config.find_proxy_handler = (env_run(setup, env) or
                env.get('find_proxy_handler'))
        except:
            print_exc()
        env.pop('add_task', None)
        handlers.clean()
        if not callable(env.get('find_proxy_handler')):
            config.find_proxy_handler = lambda self:None
            echo('\n!! Warning: You forgot to return a `find_proxy_handler(req)` '
                 'function in `config()` function.\n')
        env['web_userid'] = (conf.vget(tob, 'web_username', 'admin'),
            conf.vget(tob, 'web_password', 'admin'))
        env['web_authlocal'] = conf.vget(bool, 'web_authlocal', False)
        if conf.vget(bool, 'check_update', True): check_update()
        if tasks:
            tasks.sort(key=itemgetter(0))
            def do_tasks():
                _main = main
                t = time.time()
                for delay,func in tasks:
                    wait = t + delay - time.time()
                    if wait > 0:
                        time.sleep(wait)
                    if _main is not main: return
                    func()
            if test:
                return do_tasks()
            thread.start_new_thread(do_tasks, ())
        del config.config

    def check_update():
        file = __loader__.archive if globals().get('__loader__') else __file__
        if time.time() - _os.stat(file).st_mtime > 3600 * 24 * 30:
            def wrap(httpd):
                func = httpd.find_handler
                def find_handler(req):
                    if req.proxy_type.endswith('http') and req.path == '/':
                        httpd.find_handler = func
                        return req.send_error(302, '', ('Location: http://%s/#update'
                            '\r\n' % unparse_netloc(req.server_address, 80)))
                    return func(req)
                httpd.find_handler = find_handler
            for httpd in servers: wrap(httpd)

    def build_server(addr):
        httpd = ProxyServer(addr, ProxyHandler)
        ip, port = httpd.server_address[:2]
        addr = ProxyHandler.server_addresses
        addr.update([(ip,port), ('0.0.0.0',port), ('::',port), ('wallproxy',port)])
        if ip in ('127.0.0.1', '::1'):
            addr.add(('localhost', port))
        elif ip == '0.0.0.0':
            addr.update([('localhost', port), ('127.0.0.1', port)])
        elif ip == '::':
            addr.update([('localhost', port), ('::1', port)])
        return httpd

    def build_main_server():
        daddr = '0.0.0.0', 8086
        addr = (config.config.vget(str, 'listen_ip', daddr[0]),
            config.config.vget(int, 'listen_port', daddr[1]))
        #noinspection PyBroadException
        try:
            httpd = build_server(addr)
        except:
            echo('Warning: Listen on %s failed, listen on %s instead.\n' % (
                unparse_netloc(addr), unparse_netloc(daddr)))
            httpd = build_server(daddr)
        return httpd

    def setup():
        line = '-' * 78
        setup = get_config()
        httpd = config.httpd = build_main_server()
        servers.append(httpd)
        echo('\n'.join([line,
            'Welcome to use wallproxy, Copyright (C) 2009-2013 HustMoon Studio',
            'Version: wallproxy/%s (python/%s, gevent/%s)' % (
                __version__, sys.version.split(None,1)[0],
                gevent.__version__ if gevent else 'none'),
            'Listen : %s' % unparse_netloc(httpd.server_address[:2]),
        line, '']))
        if config.config.vget(int, 'listen_port', 8086) <= 0:
            initUrlfetch()
            config.find_proxy_handler = lambda self:None
            setup_config(setup, True)
            raise SystemExit(0)
        initCertMgr()
        initUrlfetch()
        setup_config(setup)
        echo(line + '\n')
        del config.httpd
        return httpd

    def stop_server():
        for httpd in servers[1:]: httpd.stop()
        del servers[1:]
        for func in config.__dict__.pop('server_stop', []):
            #noinspection PyBroadException
            try:
                func()
            except:
                pass

    if _os.name == 'nt':
        def notify_gui(*msg):
            import ctypes
            # def UnsetProxy():
                # class INTERNET_PER_CONN_OPTION(ctypes.Structure):
                    # class Value(ctypes.Union):
                        # _fields_ = (
                            # ('dwValue', ctypes.c_ulong),
                            # ('pszValue', ctypes.c_char_p),
                            # ('FILETIME', ctypes.c_ulong*2),
                        # )
                    # _fields_ = (
                        # ('dwOption', ctypes.c_ulong),
                        # ('Value', Value),
                    # )
                # class INTERNET_PER_CONN_OPTION_LIST(ctypes.Structure):
                    # _fields_ = (
                        # ('dwSize', ctypes.c_ulong),
                        # ('pszConnection', ctypes.c_char_p),
                        # ('dwOptionCount', ctypes.c_ulong),
                        # ('dwOptionError', ctypes.c_ulong),
                        # ('pOptions', ctypes.POINTER(INTERNET_PER_CONN_OPTION)),
                    # )
                # INTERNET_PER_CONN_FLAGS = 1
                # INTERNET_PER_CONN_PROXY_SERVER = 2
                # INTERNET_PER_CONN_AUTOCONFIG_URL = 4
                # PROXY_TYPE_DIRECT = 1
                # INTERNET_OPTION_REFRESH = 37
                # INTERNET_OPTION_SETTINGS_CHANGED = 39
                # INTERNET_OPTION_PER_CONNECTION_OPTION = 75
                # Option = (INTERNET_PER_CONN_OPTION * 3)()
                # List = INTERNET_PER_CONN_OPTION_LIST()
                # Option[0].dwOption = INTERNET_PER_CONN_PROXY_SERVER
                # Option[1].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL
                # Option[2].dwOption = INTERNET_PER_CONN_FLAGS
                # Option[0].Value.pszValue = Option[1].Value.pszValue = ''
                # Option[2].Value.dwValue = PROXY_TYPE_DIRECT
                # List.pOptions = Option
                # List.pszConnection = None
                # List.dwOptionCount = 3
                # List.dwOptionError = 0
                # List.dwSize = ctypes.sizeof(INTERNET_PER_CONN_OPTION_LIST)
                # InternetSetOption = ctypes.windll.wininet.InternetSetOptionA
                # InternetSetOption(None, INTERNET_OPTION_PER_CONNECTION_OPTION, ctypes.byref(List), List.dwSize)
                # InternetSetOption(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
                # InternetSetOption(None ,INTERNET_OPTION_REFRESH, None, 0)
                # time.sleep(1)
            msgs = {'RELOAD':204, 'RESTART':205}
            user32 = ctypes.windll.user32
            @ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)
            def EnumWindowsProc(hwnd, lParam):
                h = user32.GetPropW(hwnd, lParam)
                if h == 1:
                    for m in msg:
                        # if m == 'RELOAD': UnsetProxy()
                        user32.PostMessageW(hwnd, 0x0111, 0x0400+msgs[m], 0)
                    return 0
                return 1
            GUI_ID = u'WallProxy-7551B08E-83F5-42b5-9B6B-C8F02AC54625'
            user32.EnumWindows(EnumWindowsProc, GUI_ID)

        def restart():
            stop_server()
            name = __name__; _reload = reload
            env = globals(); env.clear()
            env['__name__'] = name; env['__doc__'] = None
            _reload(sys.modules[name])
            notify_gui('RESTART')

        def setup_once():
            if len(sys.argv) == 1:
                from ctypes import windll
                kernel32 = windll.kernel32; user32 = windll.user32
                title = 'wallproxy v%s BY HustMoon <%s>' % (__version__, __author__)
                hWnd = user32.FindWindowA(0, title)
                if hWnd:
                    user32.ShowWindow(kernel32.GetConsoleWindow(), 0)
                    if user32.IsWindowVisible(hWnd):
                        user32.ShowWindow(hWnd, 0)
                    else:
                        user32.ShowWindow(hWnd, 1)
                        user32.SetForegroundWindow(hWnd)
                    time.sleep(0.5)
                    sys.exit(1)
                else:
                    kernel32.SetConsoleTitleA(title)
        globals()['<setup_once>'] = setup_once

        def _main():
            import gc
            ENV = globals()
            ENV['<setup_once>']()
            while 1:
                del ENV['<setup_once>']
                httpd = ENV.pop('<setup>')()
                gc.collect()#; print gc.garbage
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    break
                finally:
                    ENV.pop('<reload>')()
    else:
        def restart(func):
            def setup():
                lockfile = _os.environ.get('WALLPROXY_RESTART')
                if lockfile:
                    try:
                        while ospath.isfile(lockfile):
                            _os.utime(lockfile, None)
                            time.sleep(0.5)
                    except IOError:
                        pass
                    finally:
                        time.sleep(1)
                        del _os.environ['WALLPROXY_RESTART']
                return func()
            return setup
        setup = restart(setup)

        def restart():
            stop_server()
            import subprocess, tempfile
            t, lockfile = tempfile.mkstemp('.wp'); _os.close(t)
            t = _os.stat(lockfile).st_mtime
            _os.environ['WALLPROXY_RESTART'] = lockfile
            subprocess.Popen([sys.executable] + sys.argv, close_fds=True)
            while _os.stat(lockfile).st_mtime == t: time.sleep(0.5)
            _os.unlink(lockfile)

        def _main():
            import gc
            httpd = globals().pop('<setup>')()
            gc.collect()#; print gc.garbage
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            else:
                globals().pop('<reload>')()

    DEBUG_LEAK(_main)
    globvars = globals()
    globvars['<setup>'] = setup
    globvars['<reload>'] = restart
    globvars['main'] = _main
    servers = []


    def ConnectionManager():
        Timeouts = (10, 45)
        Hostss = {}
        Domainss = {}
        Resolves = []
        BlackList = set()

        def remote_dns(domain, dns, timeout=3, tcp=False, local=False, ipv6=0, port=53):
            if domain == 'localhost': return ['127.0.0.1', '::1']
            part = ('\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00' %
                ''.join([chr(len(i))+i for i in domain.split('.')]))
            length = len(part) + 5; ips = []
            if ipv6 == 2: ipv6 = ('\x1c\x00\x01','\x01\x00\x01')
            elif ipv6 == 1: ipv6 = ('\x1c\x00\x01',)
            else: ipv6 = ('\x01\x00\x01',)
            for req in ipv6:
                id = _os.urandom(2)
                req = ''.join((id, part, req))
                for i in xrange(2):
                    sock = None
                    #noinspection PyBroadException
                    try:
                        sock = socket(AF_INET6 if ':' in dns else AF_INET,
                            SOCK_STREAM if tcp else SOCK_DGRAM)
                        sock.settimeout(timeout)
                        if tcp:
                            sock.connect((dns, port))
                            sock.sendall(struct.pack('>H', length) + req)
                            resp = sock.recv(struct.unpack('>H', sock.recv(2))[0])
                        else:
                            sock.sendto(req, (dns, port))
                            resp = sock.recv(512)
                        assert resp[:2] == id
                        cnt = struct.unpack('>H', resp[6:8])[0]; resp = resp[length:]
                        while len(resp) > 12 and cnt > 0:
                            cnt -= 1; i = resp[3]; j = 12 + ord(resp[11])
                            name = resp[12:j]; resp = resp[j:]
                            ip = None
                            if i == '\x01': ip = inet_ntoa(name)
                            elif i == '\x1c': ip = inet_ntop(AF_INET6, name)
                            if ip and ip not in BlackList: ips.append(ip)
                        break
                    except:
                        pass
                    finally:
                        if sock: sock.close()
            if ips:
                info('Resolve %r to %s with dns %s.\n' % (domain, ips, dns))
                return ips
            info('Resolve %r with dns %s failed.\n' % (domain, dns))
            if not local: raise gaierror(11004, 'getaddrinfo failed')
            return _dns_resolve(domain)

        def _dns_resolve(domain):
            try:
                ips = set(i[-1][0] for i in getaddrinfo(domain, None)) - BlackList
                if not ips: raise gaierror(11004, 'getaddrinfo failed')
                ips = list(ips)
                info('Resolve %r to %s with local dns.\n' % (domain, ips))
                return ips
            except:
                info('Resolve %r with local dns failed.\n' % domain)
                raise

        def _set_dns(dns, timeout, tcp, local, ipv6, port, blacklist):
            BlackList.clear()
            BlackList.update(blacklist)
            if dns:
                dns0 = dns[:-1]; dns1 = dns[-1]
                def handle(d):
                    for dns in dns0:
                        try:
                            return remote_dns(d, dns, timeout, tcp, False, ipv6, port)
                        except gaierror:
                            pass
                    return remote_dns(d, dns1, timeout, tcp, local, ipv6, port)
                Handle[4] = handle
            else:
                Handle[4] = _dns_resolve

        def _set_resolve(hosts):
            hosts = set(hosts.split() if isinstance(hosts, basestring) else hosts)
            ends = tuple(sorted([k for k in hosts if k.startswith('.')], key=len))
            hosts.difference_update(ends)
            Resolves[:] = hosts
            Handle[5] = ends, {}

        def _set_hosts(port, hosts, ips, mode):
            port = port and int(port) or None
            Hosts = Hostss.setdefault(port, {})
            Domains = Domainss.setdefault(port, {})
            hosts = set(hosts.split() if isinstance(hosts, basestring) else hosts)
            if not mode:
                keys = set(Hosts); keys.update(Domains)
                hosts.difference_update(keys)
                if hosts:
                    keys = tuple([k for k in keys if k.startswith('.')])
                    hosts = [k for k in hosts if not k.endswith(keys)]
            if hosts:
                ips = set(ips.split() if isinstance(ips, basestring) else ips)
                hs = set(); ds = set()
                for ip in ips:
                    try:
                        inet_pton(AF_INET6 if ':' in ip else AF_INET, ip)
                        hs.add(ip)
                    except error:
                        ds.add(ip)
                if mode == 2:
                    for ip in hosts:
                        Hosts.setdefault(ip, set()).update(hs)
                        Domains.setdefault(ip, set()).update(ds)
                else:
                    Hosts.update(dict.fromkeys(hosts, hs))
                    Domains.update(dict.fromkeys(hosts, ds))

        def _set_hosts2(port, hosts, ips, mode):
            if Handle[2] is not find_hosts:
                with runLock:
                    if Handle[2] is not find_hosts:
                        _set_hosts(port, hosts, ips, mode)
                        return _build_ends2()
            set_hosts(port, hosts, ips, mode)

        def set_hosts(port, hosts, ips, mode):
            port = port and int(port) or None
            Hosts = Hostss.get(port, {})
            hosts = set(hosts.split() if isinstance(hosts, basestring) else hosts)
            if not mode:
                keys = set(Hosts); hosts.difference_update(keys)
                if hosts:
                    keys = tuple([k for k in keys if k.startswith('.')])
                    hosts = [k for k in hosts if not k.endswith(keys)]
            if hosts:
                ips = set(ips.split() if isinstance(ips, basestring) else ips)
                keys = set()
                for ip in ips:
                    try:
                        inet_pton(AF_INET6 if ':' in ip else AF_INET, ip)
                        keys.add(ip)
                    except error:
                        try:
                            keys.update(Handle[4](ip))
                        except error:
                            pass
                    try:
                        socket(AF_INET6)
                    except error:
                        keys = [k for k in keys if ':' not in k]
                if not keys and mode == 2: return
                keys = [dict.fromkeys(keys, 0), None, Timeouts[0], 0, []]
                with runLock:
                    if mode == 2:
                        for ip in hosts:
                            ips = Hosts.get(ip)
                            if ips:
                                ips[0].update(keys[0])
                            else:
                                Hosts[ip] = keys
                    else:
                        if keys[0]:
                            Hosts.update(dict.fromkeys(hosts, keys))
                            Hostss.setdefault(port, Hosts)
                        else:
                            for ip in hosts:
                                Hosts.pop(ip, None)
                            if not Hosts:
                                Hostss.pop(port, None)

        def _show_hosts():
            return Hostss, Domainss

        def show_hosts():
            return Hostss, Handle[5][1]

        def _build_ends2():
            for port,Hosts in Hostss.iteritems():
                Domains = Domainss[port]
                for k,v in Domains.items():
                    if not (k and v): del Domains[k]
                for k,v in Hosts.items():
                    if not (k and (v or k in Domains)): del Hosts[k]
                if not Domains: del Domainss[port]
            Handle[0] = _build_ends()

        def _build_ends():
            ends = {}
            for port,Hosts in Hostss.iteritems():
                k = [k for k in Hosts if k.startswith('.')]
                k.sort(key=len, reverse=True)
                ends[port] = tuple(k)
            return ends

        def _find_hosts(address):
            if callable(Handle[0]):
                with runLock:
                    if callable(Handle[0]):
                        Handle[1] = _set_hosts2
                        if callable(Handle[5]):
                            Handle[5] = (), {}
                        _build_ends2()
            with runLock:
                connect, hosts = find_hosts(address)
            if hosts is None or connect is not hosts_connect:
                _resolve_dns(False)
            else:
                _resolve_dns(False, True)
                with runLock:
                    connect, hosts = find_hosts(address)
                if type(hosts) is not list:
                    connect = _hosts_connect
            return connect, hosts

        _dns_lock = threading.Lock()
        def _resolve_dns(net_ok, block=False):
            if block:
                with _dns_lock:
                    _resolve_dns0(net_ok)
            else:
                if _dns_lock.acquire(0):
                    thread.start_new_thread(_resolve_dns1, (net_ok,))
        def _resolve_dns1(net_ok):
            try:
                _resolve_dns0(net_ok)
            finally:
                _dns_lock.release()

        def _resolve_dns0(net_ok):
            cache = {}
            if Domainss:
                for i in xrange(2):
                    failed = set()
                    for port,Domains in Domainss.iteritems():
                        if Handle[2] is find_hosts: return
                        Hosts = Hostss[port]
                        for k,v in Domains.iteritems():
                            sets = Hosts[k]
                            for d in tuple(v):
                                if Handle[2] is find_hosts: return
                                try:
                                    sets.update(cache[d])
                                except KeyError:
                                    if d in failed: continue
                                    try:
                                        sets.update(cache.setdefault(d, Handle[4](d)))
                                        net_ok = True
                                    except gaierror:
                                        if not net_ok:
                                            failed.add(d)
                            #noinspection PyUnusedLocal
                            v &= failed
                    if not failed: break
                    if not net_ok: return
            if Handle[2] is not find_hosts:
                if Resolves:
                    d = tuple(Resolves); del Resolves[:]; Hosts = Handle[5][1]
                    sets = dict((v,v) for v in Hosts.itervalues())
                    for d in d:
                        try:
                            k = tuple(cache.get(d) or Handle[4](d))
                            Hosts[d] = sets.setdefault(k, k)
                        except gaierror:
                            pass
                with runLock:
                    if Handle[2] is not find_hosts:
                        Domainss.clear()
                        has_ipv6 = True
                        try:
                            socket(AF_INET6)
                        except error:
                            has_ipv6 = False
                        sets = {}
                        for port,Hosts in Hostss.iteritems():
                            cache = {}; d = {}
                            for k,v in Hosts.iteritems():
                                if not has_ipv6:
                                    v = [i for i in v if ':' not in i]
                                if v:
                                    v = frozenset(v)
                                    d[k] = (cache.get(v) or cache.setdefault(v,
                                        [dict.fromkeys(v, 0), None, Timeouts[0], 0, []]))
                            if d: sets[port] = d
                        Hostss.clear()
                        Hostss.update(sets)
                        Handle[0] = _build_ends()
                        Handle[1] = set_hosts
                        Handle[3] = show_hosts
                        Handle[2] = find_hosts

        def hosts_connect2(hosts, port, timeout):
            iplen = len(hosts)
            for _ in xrange(((iplen + 5) // 6) * 2):
                ips = random.sample(hosts, 6) if iplen > 6 else hosts
                socks = []
                for ip in ips:
                    sock = socket(AF_INET6 if ':' in ip else AF_INET)
                    sock.setblocking(0)
                    sock.connect_ex((ip, port))
                    socks.append(sock)
                r, w, e = select([], socks, [], timeout)
                for sock in w:
                    try:
                        sock.getpeername()
                    except error:
                        pass
                    else:
                        sock.settimeout(timeout)
                        for w in socks:
                            if w is not sock: w.close()
                        return sock
                for sock in socks: sock.close()
            raise error('connect to %s with %s failed' % (
                    unparse_netloc((runLocal.addrinfo[0], port)), list(hosts)))

        def _hosts_connect(hosts, port, timeout):
            sock = hosts_connect2(hosts, port, timeout)
            _resolve_dns(True)
            return sock

        def find_hosts((host, port)):
            connect = hosts_connect
            Hosts = Hostss.get(port)
            hosts = Hosts.get(host) if Hosts else None
            if hosts is None:
                Hosts2 = Hostss.get(None)
                if Hosts2:
                    hosts = Hosts2.get(host)
                if hosts is not None:
                    Hosts = Hosts2
                else:
                    ends3, Hosts3 = Handle[5]
                    hosts = Hosts3.get(host)
                    if hosts:
                        Hosts = Hosts3
                        connect = hosts_connect2
                    else:
                        if Hosts:
                            ends = Handle[0][port]
                            if host.endswith(ends):
                                Hosts[host] = hosts = Hosts[
                                    ifilter(host.endswith, ends).next()]
                        if hosts is None:
                            if Hosts2:
                                ends = Handle[0][None]
                                if host.endswith(ends):
                                    Hosts = Hosts2
                                    Hosts[host] = hosts = Hosts[
                                        ifilter(host.endswith, ends).next()]
                            if hosts is None and host.endswith(ends3):
                                Hosts = Hosts3
                                connect = hosts_connect2
                                try:
                                    Hosts[host] = hosts = tuple(Handle[4](host))
                                except gaierror:
                                    pass
            runLocal.addrinfo = [host, None, Hosts]
            return connect, hosts

        def _check_google_ip(iplist, count=100, timeout=10):
            host = 'autoproxy2pac.appspot.com'
            path = '/static/script.js'
            keyword = 'loadChangelog()'
            iplist = iplist.split('|') if isinstance(iplist, str) else list(iplist)
            check1 = {}; check2 = {}; ok = set(); bad = set()
            while 1:
                while iplist and len(check1) < count:
                    ip = iplist.pop()
                    sock = socket(AF_INET6 if ':' in ip else AF_INET)
                    sock.setblocking(0)
                    sock.connect_ex((ip, 443))
                    check1[sock] = (ip, time.time())
                if not check1 and not check2: break
                ws = check1.keys(); rs = check2.keys()
                r, w, e = select(rs, ws, [], 2)
                t = time.time()
                for sock in ws:
                    if sock in w:
                        ip = check1.pop(sock)[0]
                        try:
                            sock.getpeername()
                            sock.settimeout(timeout)
                            sock = ssl.wrap_socket(sock)
                            data = ('GET %s HTTP/1.1\r\n'
                                    'Host: %s\r\n'
                                    'Accept-Encoding: identity\r\n'
                                    'User-Agent: Mozilla/5.0\r\n'
                                    'Connection: close\r\n\r\n')%(path,host)
                            sock.sendall(data)
                            check2[sock] = (ip, time.time())
                        except Exception:
                            # print 'bad ip:', ip
                            bad.add(ip)
                            sock.close()
                    elif t - check1[sock][1] >= timeout:
                        # print 'bad ip:', check1[sock][0]
                        bad.add(check1.pop(sock)[0])
                        sock.close()
                for sock in rs:
                    if sock in r:
                        ip = check2.pop(sock)[0]
                        try:
                            data = sock.recv(400)
                            if keyword in data:
                                # print 'good ip:', ip
                                ok.add(ip)
                            else:
                                # print 'bad ip:', ip
                                bad.add(ip)
                        except Exception:
                            # print 'bad ip:', ip
                            bad.add(ip)
                        finally:
                            sock.close()
                    elif t - check2[sock][1] >= timeout:
                        # print 'bad ip:', check2[sock][0]
                        bad.add(check2.pop(sock)[0])
                        sock.close()
            return ok, bad

        def _collect_google_ip(backup):
            for i in xrange(2):
                try:
                    if i == 0:
                        url = URLInfo('http://users16.jabry.com/kookle/index.html')
                        fp = config.global_proxy.get_opener(url).open(url)
                        if fp.status != 200:
                            fp.close(); continue
                        date = fp.msg.getheader('Last-Modified', '')
                        if backup.get('mtime') == date:
                            fp.close(); break
                        data = re.search(r'(?ms)var list = new Array\((.+?)\);', data).group(1)
                    else:
                        url = ospath.join(misc_dir, 'ggc.dat')
                        date = datetime.utcfromtimestamp(_os.stat(url).st_mtime
                            ).strftime('%a, %d %b %Y %H:%M:%S GMT')
                        if backup.get('mtime') == date:
                            break
                        with open(url, 'rb') as fp:
                            data = fp.read().decode('base64')
                    data = re.findall(r'((?:\d{1,3}\.){3})(\d{1,3})/(\d{1,3})', data)
                    iplist = set()
                    for ip,min,max in data:
                        for i in xrange(int(min), int(max)+1):
                            iplist.add(ip + str(i))
                    info('GGC iplist: count=%d mtime=%s\n' % (len(iplist), date))
                    backup['iplist'] = _check_google_ip(iplist)[0]
                    backup['mtime'] = date
                    cache_set('google_ip', backup)
                    break
                except Exception:
                    pass
            info('GGC iplist: count=%d after first filter\n' % len(backup.get('iplist', ())))
            return backup

        def _common_reduce(iplist, port):
            timeout = Timeouts[0]
            check = {}; ok = set(); bad = set()
            while 1:
                t = time.time()
                while iplist and len(check) < 10:
                    ip = iplist.pop()
                    sock = socket(AF_INET6 if ':' in ip else AF_INET)
                    sock.setblocking(0)
                    sock.connect_ex((ip, port))
                    check[sock] = (ip, t)
                if not check: break
                socks = check.keys()
                r, w, e = select([], socks, [], timeout)
                t = time.time()
                for sock in socks:
                    if sock in w:
                        ip = check.pop(sock)[0]
                        try:
                            sock.getpeername()
                            ok.add(ip)
                        except error:
                            bad.add(ip)
                        finally:
                            sock.close()
                    elif t - check[sock][1] >= timeout:
                        bad.add(check.pop(sock)[0])
                        sock.close()
            return ok, bad

        reducing_hosts = set()
        def reduce_hosts(hosts, port, host):
            is_google = False
            with runLock:
                if hosts[3] != 0 or id(hosts) in reducing_hosts: return
                hosts[3] = 1
                score = hosts[0]
                if '2.2.2.2' in score:
                    is_google = True
                    del score['2.2.2.2']
                iplist = score.keys()
                reducing_hosts.add(id(hosts))
            try:
                oklen = len(iplist)
                if is_google:
                    backup = _collect_google_ip(cache_get('google_ip', {}))
                    ok = backup.setdefault('ok', ())
                    if ok:
                        with runLock:
                            score.clear()
                            score.update(dict.fromkeys(ok, 0))
                            hosts[1:4] = (None, Timeouts[0], 1)
                            hosts[4][:] = backup.setdefault('bad', ())
                    ok = set(backup.setdefault('iplist', ()))
                    if ok:
                        ok.update(iplist)
                        oklen = min(len(ok), 20)
                    else:
                        ok = iplist
                    bad = ok
                    while bad and len(ok) >= oklen:
                        ok, bad = _check_google_ip(ok)
                    if not ok: ok, bad = bad, ok
                    info('GGC iplist: count=%d after final filter\n' % len(ok))
                    backup['ok'] = ok; backup['bad'] = bad
                    cache_set('google_ip', backup)
                elif oklen > 1:
                    ok, bad = _common_reduce(iplist, port)
                else:
                    return
                with runLock:
                    score.clear()
                    score.update(dict.fromkeys(ok, 0))
                    hosts[1:4] = (None, Timeouts[0], 1)
                    hosts[4][:] = bad
                info('Reduce hosts for %s\n' % host)
            finally:
                reducing_hosts.remove(id(hosts))

        def hosts_connect(hosts, port, timeout):
            addrinfo = runLocal.addrinfo
            score, ip, ctimeout = hosts[:3]
            if ip:
                sock = None
                try:
                    sock = socket(AF_INET6 if ':' in ip else AF_INET)
                    sock.settimeout(ctimeout)
                    sock.connect((ip, port))
                    sock.settimeout(timeout)
                    addrinfo[1] = ip
                    return sock
                except error:
                    if sock is not None:
                        sock.close()
                    with runLock:
                        if hosts[1] == ip:
                            hosts[3] -= len(score)
                            score[ip] -= 2
                            hosts[1] = None
                            info('Deselect %s for %s\n' % (ip, addrinfo[0]))
            if hosts[3] == 0:
                thread.start_new_thread(reduce_hosts, (hosts, port, addrinfo[0]))
            iplist = score.keys(); iplen = len(iplist)
            for _ in xrange(((iplen + 5) // 6) * 2):
                ips = random.sample(iplist, 6) if iplen > 6 else iplist
                socks = []
                for ip in ips:
                    sock = socket(AF_INET6 if ':' in ip else AF_INET)
                    sock.setblocking(0)
                    sock.connect_ex((ip, port))
                    socks.append(sock)
                r, w, e = select([], socks, [], ctimeout)
                for sock in w:
                    try:
                        sock.getpeername()
                    except error:
                        pass
                    else:
                        sock.settimeout(timeout)
                        for i,w in enumerate(socks):
                            if w is sock:
                                ip = ips[i]
                            else:
                                w.close()
                        addrinfo[1] = ip
                        with runLock:
                            if ip in score:
                                score[ip] += 1
                                if not hosts[1]:
                                    hosts[3] += 1
                                    if hosts[3] >= iplen * 5:
                                        hosts[1] = max(score, key=score.__getitem__)
                                        info('Select %s for %s\n' % (hosts[1], addrinfo[0]))
                                    elif ctimeout > Timeouts[0] and hosts[3] // iplen == 0:
                                        hosts[2] -= 1
                        return sock
                for sock in socks: sock.close()
            with runLock:
                if ctimeout < Timeouts[1]:
                    hosts[2] = min(ctimeout + 5, Timeouts[1])
                score.update(dict.fromkeys(score, -1))
                score.update(dict.fromkeys(hosts[4], 0))
                hosts[1:5] = (None, Timeouts[0], 0, [])
                info('Reconfig hosts for %s\n' % addrinfo[0])
            raise error('connect to %s with %s failed' % (
                unparse_netloc((addrinfo[0], port)), iplist))

        mod_env = globals()
        o_create_connection = mod_env.setdefault('<create_connection>',
            mod_env['create_connection'])
        @functools.wraps(o_create_connection)
        def create_connection(address, *a, **kw):
            connect, hosts = Handle[2](address)
            if hosts:
                timeout = a[0] if a else kw.get('timeout', _GLOBAL_DEFAULT_TIMEOUT)
                if timeout is _GLOBAL_DEFAULT_TIMEOUT:
                    timeout = getdefaulttimeout()
                return connect(hosts, address[1], timeout)
            return o_create_connection(address, *a, **kw)
        mod_env['create_connection'] = create_connection

        def get_current_ip():
            try:
                return runLocal.addrinfo[1]
            except AttributeError:
                pass

        def del_bad_hosts():
            try:
                host, ip, Hosts = runLocal.addrinfo
            except AttributeError:
                return
            if ip:
                runLocal.addrinfo[1] = None
                hosts = Hosts[host]
                with runLock:
                    score = hosts[0]; avoid = hosts[4]
                    if ip in score:
                        score[ip] -= 2
                        if score[ip] <= 1:
                            del score[ip]
                            info('Remove %s for %s\n' % (ip, host))
                            avoid.append(ip)
                            if not score:
                                score.update(dict.fromkeys(avoid, 0))
                                hosts[1:5] = [None, Timeouts[0], 0, []]
                                info('Reconfig hosts for %s\n' % host)
                        if hosts[1] == ip:
                            hosts[3] -= len(score)
                            hosts[1] = None
                            info('Deselect %s for %s\n' % (ip, host))
                return True

        Handle = [_set_dns, _set_hosts, _find_hosts, _show_hosts, _dns_resolve, _set_resolve]
        return Handle, get_current_ip, del_bad_hosts, remote_dns

    DEBUG_LEAK(ConnectionManager)
    ConnectionManager, get_current_ip, del_bad_hosts, remote_dns = env_run(ConnectionManager, _socket.__dict__)


    def proxylib():
        class ProxyError(error):
            def __init__(self, errno, msg=''):
                if not msg and 0 <= errno <= 9:
                    msg = ('invalid response', #0
                        'general SOCKS server failure', #0x01
                        'connection not allowed by ruleset', #0x02
                        'network unreachable', #0x03
                        'host unreachable', #0x04
                        'connection refused', #0x05
                        'TTL expired', #0x06
                        'command not supported', #0x07
                        'address type not supported', #0x08
                        'authentication failed', #9
                    )[errno]
                error.__init__(self, errno, msg)

        class proxysocket(socket):
            def __init__(self, _sock=None, proxypeer=None):
                socket.__init__(self, _sock=_sock)
                if hasattr(_sock, '_sock'):
                    self._sock = _sock._sock
                if not proxypeer:
                    proxypeer = _sock.getproxypeer()
                self.__proxypeer = proxypeer

            def getproxypeer(self):
                return self.__proxypeer

        def parse_proxy(proxy):
            scheme, host, path = urlsplit(proxy)
            username, password, host = parse_userloc(host)
            if scheme == 'socks': scheme = 'socks5'
            host, port = parse_netloc(host, default_ports.get(scheme, 80))
            if scheme == 'hosts':
                userid = None
            elif scheme in ('http', 'https', 'socks5'):
                if username is None or password is None:
                    userid = None
                else:
                    userid = username, password
            elif scheme == 'socks4':
                userid = '' if username is None else (
                    username if password is None else username+':'+password)
            else:
                raise ValueError('Invalid proxy type: ' + scheme)
            dns = 'dns=1' in path.lower()
            return scheme, (host, port), userid, dns

        response_class = httplib.HTTPResponse
        class Proxy(object):
            _proxysocket = proxysocket
            handlers = {}
            PROXIES = WeakValueDictionary()
            https_mode = None

            @classmethod
            def _new_proxy(cls, proxy):
                self = cls.PROXIES.get(proxy)
                if not self:
                    cls.PROXIES[proxy] = self = object.__new__(cls)
                    self.value = proxy
                    if proxy:
                        p = [p[0] for p in proxy]
                        self._info = ('socks4' in p or 'socks5' in p or 'https' in p,
                            p[-1] not in ('hosts', 'http'))
                        if p[-1] == 'http':
                            self.userid = proxy[-1][2]
                            proxy = list(proxy)
                            proxy[-1] = ('https',) + proxy[-1][1:]
                            self.https_mode = cls._new_proxy(tuple(proxy))
                return self

            def __new__(cls, proxy=None):
                if isinstance(proxy, cls):
                    return proxy
                elif not proxy:
                    proxy = None
                else:
                    if isinstance(proxy, basestring):
                        proxy = (proxy,)
                    p = []
                    for i in xrange(len(proxy)-1):
                        p.append(parse_proxy(proxy[i]))
                        if p[-1][0] in ('hosts', 'http'):
                            raise ValueError('Invalid proxies order')
                    p.append(parse_proxy(proxy[-1]))
                    proxy = tuple(p)
                return cls._new_proxy(proxy)

            def new_hosts(self, addr):
                if not self.value: return self
                addr = 'hosts', addr, None, False
                p = list((self.https_mode or self).value)
                if p[-1][0] == 'hosts':
                    p[-1] = addr
                else:
                    p.append(addr)
                return self._new_proxy(tuple(p))

            #noinspection PyMethodParameters
            def connect(sock, addr, auth, dns, cmd):
                if not isinstance(cmd, int):
                    cmd = 1
                elif cmd not in (1, 2):
                    raise ProxyError(7) #command not supported
                addr, port = addr
                if dns:
                    addr = gethostbyname(addr)
                try:
                    req = inet_aton(addr)
                    dns = True
                    req = ''.join(('\x04', struct.pack('>BH', cmd, port),
                        req, auth, '\x00'))
                except error: #try SOCKS 4a
                    dns = False
                    req = '\x04%s\x00\x00\x00\x01%s\x00%s\x00' % (
                        struct.pack('>BH', cmd, port), auth, addr)
                sock.sendall(req)
                resp = sock.recv(8)
                if resp[0] != '\x00':
                    raise ProxyError(0) #invalid response
                if resp[1] != '\x5a':
                    if resp[1] == '\x5b': raise ProxyError(5) #connection refused
                    if resp[1] == '\x5c': raise ProxyError(4) #host unreachable
                    if resp[1] == '\x5d': raise ProxyError(9) #authentication failed
                    raise ProxyError(0) #invalid response
                if dns:
                    return addr, port
                return inet_ntoa(resp[4:]), struct.unpack('>H',resp[2:4])[0]
            handlers['socks4'] = connect

            #noinspection PyMethodParameters
            def connect(sock, addr, auth, dns, cmd):
                if not isinstance(cmd, int):
                    cmd = 1
                elif cmd not in (1, 2, 3):
                    raise ProxyError(7) #command not supported
                sock.sendall('\x05\x02\x00\x02' if auth else '\x05\x01\x00')
                resp = sock.recv(2)
                if resp[0] != '\x05':
                    raise ProxyError(0) #invalid response
                if resp[1] == '\x02':
                    sock.sendall(''.join(('\x01', chr(len(auth[0])), auth[0],
                        chr(len(auth[1])), auth[1])))
                    resp = sock.recv(2)
                if resp[1] != '\x00':
                    raise ProxyError(9) #authentication failed
                addr, port = addr
                if dns:
                    addr = getaddrinfo(addr, port)[-1][-1][0]
                if ':' in addr: #IPv6
                    addr = '\x04' + inet_pton(AF_INET6, addr)
                else:
                    try:
                        addr = '\x01' + inet_aton(addr) #IPv4
                    except error:
                        addr = ''.join(('\x03', chr(len(addr)), addr)) #domain
                req = ''.join(('\x05', chr(cmd), '\x00', addr, struct.pack('>H',port)))
                sock.sendall(req)
                resp = sock.recv(4)
                if resp[0] != '\x05':
                    raise ProxyError(0) #invalid response
                if resp[1] != '\x00':
                    raise ProxyError(ord(resp[1]))
                if resp[3] == '\x01': #IPv4 address
                    addr = inet_ntoa(sock.recv(4))
                elif resp[3] == '\x03': #Domain name
                    addr = sock.recv(ord(sock.recv(1)))
                elif resp[3] == '\x04': #IPv6 address
                    addr = inet_ntop(AF_INET6, sock.recv(16))
                else:
                    raise ProxyError(8) #address type not supported
                port = struct.unpack('>H',sock.recv(2))[0]
                return addr, port
            handlers['socks5'] = connect

            #noinspection PyMethodParameters
            def connect(sock, addr, auth, dns, cmd):
                if isinstance(cmd, basestring):
                    cmd = 'Proxy-Authorization: %s\r\n' % cmd
                elif not isinstance(cmd, int) or cmd == 1:
                    cmd = ''
                else:
                    raise ProxyError(7) #command not supported
                addr, port = addr
                hostinfo = ('[%s]:%d' if ':' in addr else '%s:%d') % (addr, port)
                if dns:
                    addr = getaddrinfo(addr, port)[-1][-1][0]
                    req = ('[%s]:%d' if ':' in addr else '%s:%d') % (addr, port)
                else:
                    req = hostinfo
                req = ('CONNECT %s HTTP/1.0\r\n%%s'
                       'Proxy-Connection: keep-alive\r\n'
                       'Host: %s\r\n\r\n') % (req, hostinfo)
                authinfo = ('Proxy-Authorization: Basic %s\r\n' % b64encode(
                    '%s:%s' % auth)) if auth else cmd
                # print 'send: %r' % (req % authinfo)
                sock.sendall(req % authinfo)
                resp = response_class(sock)#, debuglevel=1)
                try:
                    resp.begin()
                    if resp.length: resp.read()
                except:
                    raise ProxyError(0) #invalid response
                code = resp.status
                if code == 200:
                    return addr, port
                elif code == 407:
                    authinfo = resp.msg.get('Proxy-Authenticate').split(None, 1)
                    if auth and len(authinfo)==2 and authinfo[0].lower()=='digest':
                        authinfo = 'Proxy-Authorization: %s\r\n' % digest_client(
                            'CONNECT', '/', authinfo[1], auth)
                    else:
                        raise ProxyError(9) #authentication failed
                else:
                    raise error('CONNECT failed: %d %r' % (code, resp.reason))
                sock.sendall(req % authinfo)
                # print 'send: %r' % (req % authinfo)
                resp = response_class(sock)#, debuglevel=1)
                try:
                    resp.begin()
                    if resp.length: resp.read()
                except:
                    raise ProxyError(0) #invalid response
                if resp.status != 200:
                    raise ProxyError(9) #authentication failed
                return addr, port
            handlers['https'] = connect

            def connect(self, addr, timeout, cmd=1):
                p = self.value
                if not p:
                    sock = create_connection(addr, timeout)
                else:
                    sock = create_connection(p[0][1], timeout)
                    if self._info[0]:
                        handlers = self.handlers
                        cmd = cmd or 1
                        for i in xrange(len(p)-1):
                            handlers[p[i][0]](
                                sock, p[i+1][1], p[i][2], p[i][3], cmd)
                        if self._info[1]:
                            addr = handlers[p[-1][0]](
                                sock, addr, p[-1][2], p[-1][3], cmd)
                return self._proxysocket(sock, addr)

        return ProxyError, Proxy

    DEBUG_LEAK(proxylib)
    ProxyError, Proxy = env_run(proxylib, _socket.__dict__)

    class URLInfo(object):
        def __init__(self, url=None, **kw):
            if isinstance(url, URLInfo):
                self.__dict__.update(url.__dict__)
            elif url:
                self.url = url
                self.scheme, self.host, self.path = urlsplit(url)
                self.hostname, self.port = parse_netloc(self.host,
                    default_ports.get(self.scheme))
            if kw:
                self.__dict__.update(kw)
                self.rebuild()

        def __str__(self):
            return self.url

        def rebuild(self):
            host = self.host = unparse_netloc((self.hostname, self.port),
                default_ports.get(self.scheme))
            self.url = '%s://%s%s' % (self.scheme, host, self.path)
            return self

    def fetchlib():
        def _read_chunked(self, amt):
            assert self.chunked != _UNKNOWN
            chunk_left = self.chunk_left
            value = []
            while True:
                if chunk_left is None:
                    rawline = self.fp.readline()
                    line = rawline.split(';', 1)[0] # strip chunk-extensions
                    try:
                        chunk_left = int(line, 16)
                    except ValueError:
                        self.chunked = 0
                        line = len(rawline)
                        try:
                            self.length = int(self.msg.get('Content-Length', '')) - line
                            if self.length < 0: self.length = 0
                        except ValueError:
                            self.length = None if rawline else 0
                            self.will_close = 1
                        return rawline + self.read(amt - line)
                    if not chunk_left:
                        break
                if amt is None:
                    value.append(self._safe_read(chunk_left))
                elif amt < chunk_left:
                    value.append(self._safe_read(amt))
                    self.chunk_left = chunk_left - amt
                    return ''.join(value)
                elif amt == chunk_left:
                    value.append(self._safe_read(amt))
                    self._safe_read(2)  # toss the CRLF at the end of the chunk
                    self.chunk_left = None
                    return ''.join(value)
                else:
                    value.append(self._safe_read(chunk_left))
                    amt -= chunk_left

                # we read the whole chunk, get another
                self._safe_read(2)      # toss the CRLF at the end of the chunk
                chunk_left = None

            # read and discard trailer up to the CRLF terminator
            ### note: we shouldn't have any trailers!
            while True:
                line = self.fp.readline()
                if not line:
                    # a vanishingly small number of sites EOF without
                    # sending the trailer
                    break
                if line == '\r\n':
                    break

            # we read everything; close the "file"
            self.close()

            return ''.join(value)
        HTTPResponse._read_chunked = _read_chunked

        class FetchArgs(object):
            _user_agent = 'Mozilla/5.0'
            digest_info = None
            keep_alive = True
            timeout = 60
            proxy_auth = None
            crlf = 0

            def __init__(self, kw):
                if isinstance(kw, FetchArgs):
                    self.__dict__.update(kw.__dict__)
                elif kw:
                    self.__dict__.update(kw)
            update = __init__

        class HTTPFetch(HTTPConnection):
            def __init__(self, proxy, kw=None):
                self.proxy = proxy
                self.kw = FetchArgs(kw)
                self.address = None
                self.sock = None
                self._buffer = []
                self._HTTPConnection__response = None
                self._HTTPConnection__state = _CS_IDLE

            def connect(self):
                self.sock = self.proxy.connect(
                    self.address, self.kw.timeout, self.kw.proxy_auth)

            def putrequest(self, method, url, headers):
                proxy = self.proxy
                isHttpProxy = proxy.https_mode and url.scheme == 'http'
                val = url.hostname, url.port
                if self.address != val:
                    if not isHttpProxy: self.close()
                    self.address = val
                if self._HTTPConnection__state == _CS_IDLE:
                    self._HTTPConnection__state = _CS_REQ_STARTED
                else:
                    raise CannotSendRequest()
                self._method = method; kw = self.kw
                crlf = 0 if url.scheme == 'https' else kw.crlf
                val = 'HEAD / HTTP/1.1\r\n\r\n\r\n' if (crlf & 1) else ''
                if isHttpProxy:
                    if crlf & 2: val = '\r\n' + val
                    self._output('%s%s %s %s' % (val,
                        method, url.url, self._http_vsn_str))
                    self.putheader('Proxy-Connection',
                        'keep-alive' if kw.keep_alive else 'close')
                    proxy = proxy.userid
                    if proxy:
                        self.putheader('Proxy-Authorization', digest_client(method,
                        url.path, kw.digest_info, proxy) if kw.digest_info
                        else ('Basic %s' % (b64encode('%s:%s' % proxy))))
                    elif kw.proxy_auth:
                        self.putheader('Proxy-Authorization', kw.proxy_auth)
                else:
                    self._output('%s%s %s %s' % (val,
                        method, url.path, self._http_vsn_str))
                    self.putheader('Connection',
                        'keep-alive' if kw.keep_alive else 'close')
                if self._http_vsn == 11:
                    if 'Host' not in headers:
                        self.putheader('Host', url.host)
                    if 'Accept-Encoding' not in headers:
                        self.putheader('Accept-Encoding', 'identity')
                    if 'User-Agent' not in headers:
                        self.putheader('User-Agent', kw._user_agent)

            def _send_request(self, method, url, body, headers):
                if isinstance(body, list):
                    rfile, clen = body
                    if not rfile:
                        raise CannotSendRequest()
                else:
                    rfile, clen = None, 0
                self.putrequest(method, url, headers)
                if body:
                    if 'Content-Type' not in headers:
                        self.putheader('Content-Type',
                                       'application/x-www-form-urlencoded')
                    if 'Content-Length' not in headers:
                        self.putheader('Content-Length',
                            str(clen if rfile else len(body)))
                for k,v in headers.iteritems():
                    self.putheader(k, v)
                self.endheaders()
                if rfile:
                    body[0] = None
                    body = rfile.read(min(8192, clen))
                    while body:
                        self.sock.sendall(body)
                        clen -= len(body)
                        if clen <= 0: break
                        body = rfile.read(min(8192, clen))
                elif body:
                    self.send(body)
                if url.scheme != 'https' and (self.kw.crlf & 3):
                    self.response_class(self.sock, method='HEAD').begin()

            def _open(self, method, url, body, headers):
                try:
                    self.request(method, url, body, headers)
                    resp = self.getresponse()
                except (socket.error, BadStatusLine), e:
                    self.close()
                    if isinstance(body, list) and not body[0]:
                        raise
                    if isinstance(e, BadStatusLine):
                        info('%s %s: BadStatusLine, try again.\n' % (method, url.url))
                    elif del_bad_hosts():
                        info('%s %s: %s, try again.\n' % (method, url.url, e))
                    else:
                        raise
                    self.request(method, url, body, headers)
                    resp = self.getresponse()
                if resp.status == 407 and self.proxy.https_mode:
                    authinfo = resp.msg.get('Proxy-Authenticate').split(None, 1)
                    if (self.proxy.userid and
                        len(authinfo) == 2 and authinfo[0].lower() == 'digest'):
                        self.kw.digest_info = authinfo[1]
                        if resp.length: resp.read()
                        self.request(method, url, body, headers)
                        resp = self.getresponse()
                return resp

            def open(self, url, body=None, method=None,
                     headers=HeaderDict(), redirect=10):
                # if not isinstance(url, URLInfo):
                    # url = URLInfo(url)
                if not method: method = 'POST' if body else 'GET'
                # if not isinstance(headers, HeaderDict):
                    # headers = HeaderDict(headers)
                del headers['Connection'], headers['Proxy-Connection']
                resp = self._open(method, url, body, headers)
                if redirect and (resp.status in (301, 302, 303) or (resp.status==307
                    and method=='GET')) and not isinstance(body, list):
                    for ttt in xrange(redirect):
                        ttt = resp.msg.get('Location') or resp.msg.get('Uri', '')
                        url = URLInfo(urljoin(url.url, ttt))
                        ttt = self.proxy.get_opener(url, self.kw)
                        if resp.status == 303:
                            method, body = 'GET', None
                        resp.close()
                        resp = ttt._open(method, url, body, headers)
                        if resp.status not in (301, 302, 303, 307):
                            break
                return resp

        URLFetch = {'http': HTTPFetch}
        if ssl:
            class HTTPSFetch(HTTPFetch):
                def connect(self):
                    self.sock = ssl.wrap_socket((self.proxy.https_mode or self.proxy
                        ).connect(self.address, self.kw.timeout, self.kw.proxy_auth))
            URLFetch['https'] = HTTPSFetch

        return FetchArgs, URLFetch

    DEBUG_LEAK(fetchlib)
    FetchArgs, URLFetch = env_run(fetchlib, httplib.__dict__)

    def initUrlfetch():
        echo('Initializing UrlFetch for url fetch:\n')
        conf = config.config

        proxy = conf.get('global_proxy')
        try:
            config.global_proxy = Proxy(proxy)
            if proxy: echo('  Global proxy: %s\n' % (proxy,))
        except Exception, e:
            config.global_proxy = Proxy(None)
            echo('  !! Bad global_proxy %r: %s\n' % (proxy, e))
        def urlfetch(url, *a, **kw):
            if not isinstance(url, URLInfo):
                url = URLInfo(url)
            proxy = kw.pop('proxy', 'default')
            proxy = config.global_proxy if proxy == 'default' else Proxy(proxy)
            return proxy.get_opener(url).open(url, *a, **kw)
        utils.urlfetch = urlfetch

        HTTPFetch = URLFetch['http']
        HTTPFetch.debuglevel = config.debuglevel = conf.vget(int, 'debuglevel', -1)
        if config.debuglevel >= 0:
            echo('  Debug level: %d\n' % config.debuglevel)

        timeout = conf.aget(float, 'fetch_timeout', FetchArgs.timeout, None)
        keep_alive = conf.vget(bool, 'fetch_keepalive', FetchArgs.keep_alive)
        FetchArgs.timeout = timeout; FetchArgs.keep_alive = keep_alive
        echo('  Global timeout: %s\n' % timeout)
        echo('  Use keep alive: %s\n' % ('YES' if keep_alive else 'NO'))
        def get_opener(self, url, kw=None):
            openers = getattr(runLocal, 'openers', None)
            if openers is None:
                runLocal.openers = openers = {}
            scheme = url.scheme
            if self.https_mode and scheme == 'http':
                key = id(self), scheme
            else:
                key = id(self), scheme, url.host
            opener = openers.get(key)
            if not opener:
                openers[key] = opener = URLFetch[scheme](self, kw)
            elif kw:
                opener.kw.update(kw)
            return opener
        Proxy.get_opener = get_opener

    def start_new_server(address, find_handler=None):
        if isinstance(address, basestring):
            address = address.rsplit(':', 1)
        elif isinstance(address, int):
            address = address,
        if len(address) == 1:
            address = config.httpd.server_address[0], address[0]
        address = address[0], int(address[1])
        httpd = build_server(address)
        if find_handler:
            httpd.find_handler = find_handler
        thread.start_new_thread(httpd.serve_forever, ())
        servers.append(httpd)
        return httpd

    def get_main_address(target=None):
        ip, port = config.httpd.server_address[:2]
        if ip == '0.0.0.0':
            ip = '127.0.0.1'
        elif ip == '::':
            ip = '::1'
        if not target: return ip, port
        httpd_listen = unparse_netloc((ip, port))
        httpd_ip = unparse_netloc((ip, ''))
        if not isinstance(target, basestring):
            return ip, port, (lambda t: t.replace('*:*', httpd_listen).replace('*:', httpd_ip))
        return target.replace('*:*', httpd_listen).replace('*:', httpd_ip)

    # utils module
    utils = new_module(__name__+'.utils', 
        __version__ = __version__,
        tou = tou, tob = tob,
        misc_dir = misc_dir,
        cache_get = cache_get,
        cache_set = cache_set,
        parse_netloc = parse_netloc,
        unparse_netloc = unparse_netloc,
        URLInfo = URLInfo,
        digest_auth = digest_auth,
        digest_client = digest_client,
        HeaderDict = HeaderDict,
        get_current_ip = get_current_ip,
        del_bad_hosts = del_bad_hosts,
        remote_dns = remote_dns,
        ProxyError = ProxyError,
        Proxy = Proxy,
        FetchArgs = FetchArgs,
        URLFetch = URLFetch,
        start_new_server = start_new_server,
        get_main_address = get_main_address,
    )
    # globals()['utils'] = utils


    def util_plugin():
        echo('Initializing Utility for proxy-auth, hosts, forward.\n')
        _timeout = config.config.aget(float, 'forward_timeout', FetchArgs.timeout, None)
        echo('  Forward timeout: %s\n' % _timeout)

        def _digest_auth(req, username, password):
            return digest_auth(req.command, req.userid,
                'wallproxy Proxy Authenticate', (username, password),
                req.client_address[0])

        def check_auth(username, password, socks4=True, socks5=True, digest=True):
            socks5_userid = (username, password)
            socks4_userid = '%s:%s' % socks5_userid
            if not password:
                socks4_userid = username
                #noinspection PyUnusedLocal
                def http_auth(req): pass
            elif digest:
                digest_userid = socks5_userid
                def http_auth(req):
                    return digest_auth(req.command, req.userid,
                        'wallproxy Proxy Authenticate', digest_userid,
                        req.client_address[0])
            else:
                basic_userid = 'Basic ' + b64encode(socks4_userid)
                def http_auth(req):
                    if req.userid != basic_userid:
                        return 'Basic realm="wallproxy Proxy Authenticate"'
            if not socks4: socks4_userid = False
            if not socks5: socks5_userid = False
            def decorator(func):
                @functools.wraps(func)
                def wrapper(req):
                    proxy_type = req.proxy_type
                    if proxy_type == 'socks4':
                        if req.userid != socks4_userid:
                            return False
                    elif proxy_type == 'socks5':
                        if req.userid != socks5_userid:
                            return False
                    elif proxy_type in ('https', 'http'):
                        auth = http_auth(req)
                        if auth: return auth
                    req.userid = None
                    return func(req)
                return wrapper
            return decorator

        def set_dns(dns, timeout=3, tcp=True, local=True, ipv6=0, port=53, blacklist=''):
            dns = dns.split('|') if dns else []
            blacklist = blacklist.split('|') if blacklist else []
            echo('  Remote DNS: %s:%d (%s,%ds,%s,%s,%dB)\n' % (dns, port,
                'TCP' if tcp else 'UDP', timeout, 'L' if local else 'R',
                'IPv6' if ipv6 == 1 else ('IPv6&IPv4' if ipv6 == 2 else 'IPv4'), len(blacklist)))
            return ConnectionManager[0](dns, timeout, tcp, local, ipv6, port, blacklist)

        def set_resolve(hosts):
            return ConnectionManager[5](hosts)

        def set_hosts(hosts, ips, mode=1):
            port = None
            if isinstance(hosts, basestring):
                if '@' in hosts:
                    hosts, port = hosts.rsplit('@', 1)
            elif len(hosts) == 2 and isinstance(hosts[1], int):
                hosts, port = hosts
            return ConnectionManager[1](port, hosts, ips, mode)

        def redirect_https(req):
            return req.send_error(301, '',
                'Location: %s\r\n' % req.url.replace('http://', 'https://', 1))

        class Forward(object):
            handlers = {}
            timeout = _timeout
            handler_name = 'FWD'

            def get_failed_hosts(self):
                key = 'Forward.%d.failed_hosts' % id(self)
                hosts = getattr(runLocal, key, None)
                if hosts is None:
                    hosts = {}
                    setattr(runLocal, key, hosts)
                return hosts

            def __init__(self, proxy='default', name=None, timeout=-1):
                if proxy == 'default':
                    self.proxy = config.global_proxy
                else:
                    self.proxy = Proxy(proxy)
                if self.proxy.value:
                    self._msg = 'Connect other proxy failed'
                else:
                    self._msg = 'Connect server failed'
                if name:
                    self.handler_name = name
                if timeout is None or timeout >= 0:
                    self.timeout = timeout

            def __call__(self, req, fallback=None):
                proxy_type = req.proxy_type
                if (req.server_address[1] == req.proxy_host[1] and
                    req.server_address[0] in [i[-1][0]
                        for i in _socket.getaddrinfo(req.proxy_host[0], None)]):
                    if proxy_type == 'socks4':
                        return req.fake_socks4()
                    elif proxy_type == 'socks5':
                        return req.fake_socks5()
                    elif proxy_type == 'https':
                        return req.fake_https()
                    return req.http_to_web()
                req.handler_name = self.handler_name
                self.handlers[proxy_type](self, req, fallback)

            def handle(self, req, fallback):
                if fallback:
                    failed_hosts = self.get_failed_hosts()
                    if failed_hosts.get(req.proxy_host) is fallback:
                        return fallback(req)
                url = URLInfo(req.url)
                if req.content_length > 64 * 1024:
                    data = [req.rfile, req.content_length]
                else:
                    data = req.read_body()
                try:
                    resp = self.proxy.get_opener(url, {'timeout':self.timeout,
                            'crlf':getattr(req, 'crlf', 0), 'proxy_auth':req.userid}
                        ).open(url, data, req.command, req.headers, 0)
                    req.content_length = 0
                except Exception, e:
                    if fallback and (not data or (isinstance(data, list) and data[0])):
                        info('Forward %s: %s, try fallback handler.\n' % (url.url, e))
                        #noinspection PyUnboundLocalVariable
                        failed_hosts[req.proxy_host] = fallback
                        return fallback(req)
                    if isinstance(e, ProxyError):
                        return req.send_error(502, self._msg)
                    return req.send_error(502, '%s: %s' % (self._msg, e))
                req.start_response(resp.status, resp.msg, resp.reason)
                sendall = req.socket.sendall
                data = resp.read(8192)
                while data:
                    sendall(data)
                    data = resp.read(8192)
                resp.close()
            handlers['http']=handlers['socks2http']=handlers['https2http']=handle

            def handle(self, req, fallback):
                try:
                    sock = (self.proxy.https_mode or self.proxy).connect(
                        req.proxy_host, self.timeout, req.command)
                except ProxyError, e:
                    if fallback:
                        info('Forward socks4://%s: %s, try fallback handler.\n'
                            % (unparse_netloc(req.proxy_host), e))
                        if callable(fallback):
                            self.get_failed_hosts()[req.proxy_host] = fallback
                            return fallback(req)
                        self.get_failed_hosts()[req.proxy_host] = fallback[0]
                        return req.fake_socks4()
                    e = {4:'\x5c', 9:'\x5d'}.get(e.args[0], '\x5b')
                    return req.end_socks('\x00'+e+'\x00\x00\x00\x00\x00\x00')
                except _socket.error:
                    return req.end_socks('\x00\x5c\x00\x00\x00\x00\x00\x00')
                ip, port = sock.getproxypeer()
                #noinspection PyBroadException
                try:
                    ip = _socket.gethostbyname(ip)
                except:
                    ip = '0.0.0.0'
                ip = _socket.inet_aton(ip)
                req.end_socks('\x00\x5a'+struct.pack('>H',port)+ip, True)
                req.copy_sock(sock)
            handlers['socks4'] = handle

            def handle(self, req, fallback):
                try:
                    sock = (self.proxy.https_mode or self.proxy).connect(
                        req.proxy_host, self.timeout, req.command)
                except ProxyError, e:
                    if fallback:
                        info('Forward socks5://%s: %s, try fallback handler.\n'
                            % (unparse_netloc(req.proxy_host), e))
                        if callable(fallback):
                            self.get_failed_hosts()[req.proxy_host] = fallback
                            return fallback(req)
                        self.get_failed_hosts()[req.proxy_host] = fallback[0]
                        return req.fake_socks5()
                    e = e.args[0]
                    if e<1 or e>8: e = 1
                    return req.end_socks('\x05'+chr(e)+
                        '\x00\x01\x00\x00\x00\x00\x00\x00')
                except _socket.error:
                    return req.end_socks('\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                ip, port = sock.getproxypeer()
                if ':' in ip:
                    #noinspection PyBroadException
                    try:
                        ip = '\x04' + _socket.inet_pton(_socket.AF_INET6, ip)
                    except:
                        ip = '\x01\x00\x00\x00\x00'
                else:
                    #noinspection PyBroadException
                    try:
                        ip = '\x01' + _socket.inet_aton(ip) #IPv4
                    except:
                        ip = '\x03' + chr(len(ip)) + ip #domain
                req.end_socks('\x05\x00\x00' + ip + struct.pack('>H',port), True)
                req.copy_sock(sock)
            handlers['socks5'] = handle

            def handle(self, req, fallback):
                try:
                    sock = (self.proxy.https_mode or self.proxy).connect(
                        req.proxy_host, self.timeout, req.userid)
                except (ProxyError, _socket.error), e:
                    if fallback:
                        info('Forward https://%s: %s, try fallback handler.\n'
                            % (unparse_netloc(req.proxy_host, 443), e))
                        if callable(fallback):
                            self.get_failed_hosts()[req.proxy_host] = fallback
                            return fallback(req)
                        self.get_failed_hosts()[req.proxy_host] = fallback[0]
                        return req.fake_https()
                    return req.send_error(502, self._msg)
                req.log_request(200)
                req.socket.sendall('HTTP/1.0 200 OK\r\n\r\n')
                req.copy_sock(sock)
            handlers['https'] = handle
            del handle

        globals().update(
            digest_auth = _digest_auth,
            check_auth = check_auth,
            set_dns = set_dns,
            set_resolve = set_resolve,
            set_hosts = set_hosts,
            redirect_https = redirect_https,
            Forward = Forward,
        )

    DEBUG_LEAK(util_plugin)

    def pac_plugin():
        echo('Initializing PAC for proxy auto-config.\n')

        def dnsDomainIs(host, domain):
            if isinstance(domain, basestring):
                if host == domain: return True
                if not domain.startswith('.'): domain = '.' + domain
            else:
                if host in domain: return True
                domain = tuple(d if d.startswith('.') else '.'+d for d in domain)
            return host.endswith(domain)

        def dnsResolve(domain):
            try:
                return _socket.gethostbyname(domain)
            except _socket.gaierror:
                return ''
        if gevent_patch_dns:
            _dns = dnsResolve
            def dnsResolve(domain):
                return gevent.with_timeout(5, _dns, domain, timeout_value='')

        def dnsResolve2(domain):
            try:
                return _socket.getaddrinfo(domain, None)[-1][-1][0]
            except (_socket.gaierror, IndexError):
                return ''
        if gevent_patch_dns:
            _dns2 = dnsResolve2
            def dnsResolve2(domain):
                return gevent.with_timeout(5, _dns2, domain, timeout_value='')

        def ip2int(ip):
            try:
                return struct.unpack('>I', _socket.inet_aton(ip))[0]
            except _socket.error:
                return -1

        _early_match = (lambda *a: False), (lambda *a: True)

        class IpList(object):
            def match(self, ip):
                iplist = self.iplist
                start = 0; end = len(iplist)
                while start < end:
                    i = (start + end) // 2
                    sip, eip = iplist[i]
                    if sip <= ip <= eip:
                        return True
                    elif ip < sip:
                        #noinspection PyUnusedLocal
                        end = i
                    else:
                        start = i + 1
                return False

        class RuleList(object):
            def match(self, url, host):
                rule = self.rulelist
                url = url.lower()
                ishttp = (url.split('://', 1)[0] == 'http')
                host = host.split('.')
                # BlackKeyWord, Whitekw, bkw
                # bHostHash, whh, bhh
                # bUrlRegexp, wur, bur
                for i in range(3):
                    if ishttp:
                        for k in rule[i]:
                            if k in url:
                                return i != 1
                    r = rule[i+3]
                    if r:
                        for k in host:
                            for k in r.get(k, ()):
                                if k.search(url):
                                    return i != 1
                    for k in rule[i+6]:
                        if k.search(url):
                            return i != 1
                return False

        def _parseIpList(text):
            rules = re.findall(r'(\d+\.\d+\.\d+\.\d+)([|/])(\d+)', text)
            iplist = []
            for ip,sep,n in rules:
                try:
                    ip = struct.unpack('>I', _socket.inet_aton(ip))[0]
                    n = int(n)
                except _socket.error:
                    continue
                if sep == '/':
                    if n > 32: continue
                    n = (-1 << (32 - n)) & 0xffffffff
                    ip &= n
                    end = ip | (~n & 0xffffffff)
                else:
                    end = ip + n - 1
                iplist.append((ip, end))
            return iplist

        def _buildIpList(iplist):
            if len(iplist) > 1:
                iplist.sort(key=itemgetter(0))
                tmp = iter(iplist); iplist = [tmp.next()]
                for x in tmp:
                    if x[0] <= iplist[-1][1]+1:
                        iplist[-1] = iplist[-1][0], max(x[1], iplist[-1][1])
                    else:
                        iplist.append(x)
            return tuple(iplist)

        def _makeIpList(text):
            return _buildIpList(_parseIpList(text))

        def _sumRule((keyword, hash, regxep)):
            k = map(len, keyword)
            hk = map(len, hash)
            hv = [sum([len(v) for v in d.itervalues()]) for d in hash]
            r = map(len, regxep)
            return 'k%d|%d|%d+h%d:%d|%d:%d|%d:%d+r%d|%d|%d=%d' % (
                k[0], k[1], k[2], hk[0], hv[0], hk[1], hv[1], hk[2], hv[2],
                r[0], r[1], r[2], sum(k+hv+r))

        def _parseRule(rule):
            keyword = [set(), set(), set()]
            hash = [{}, {}, {}]
            regxep = [set(), set(), set()]
            for line in rule.splitlines():
                # Ignore the first line ([AutoProxy x.x]), empty lines and comments
                rule = line.strip()
                if not rule or rule.startswith(('[','!','#',';')):
                    continue
                rule_type = 2
                if rule.startswith('@@'): # White Exceptions
                    rule = rule[2:]
                    rule_type = 1
                elif rule.startswith('@'): # Black Exceptions
                    rule = rule[1:]
                    rule_type = 0
                if rule[0]=='/' and rule[-1]=='/': # Regular expressions
                    rule = rule[1:-1]
                else:
                    rule = rule.lower()
                    # Strictly mapping to keyword blocking
                    if rule.startswith('||') and '/' not in rule: rule += '/'
                    rule = re.sub(r'^(http.?://)', r'|\1', rule)
                    if rule[0]!='|' and '*' not in rule: # Maybe keyword
                        i1 = rule.find('.'); i2 = rule.find('/')
                        if i1 == -1 or i2 == -1 or i2 < i1:
                            keyword[rule_type].add(rule)
                            continue
                    # Remove multiple wildcards
                    rule = re.sub(r'\*+', '*', rule)
                    # Remove anchors following separator placeholder
                    rule = re.sub(r'\^\|$', '^', rule, 1)
                    # Escape special symbols
                    rule = re.sub(r'(\W)', r'\\\1', rule)
                    # Replace wildcards by .*
                    rule = re.sub(r'\\\*', '.*', rule)
                    # Process separator placeholders
                    rule = re.sub(r'\\\^', r'(?:[^\w\-.%\u0080-\uFFFF]|$)', rule)
                    # Process extended anchor at expression start
                    rule = re.sub(r'^\\\|\\\|', r'^https?:\/+(?:[^\/]+\.)?', rule, 1)
                    # Process anchor at expression start
                    rule = re.sub(r'^\\\|', '^', rule, 1)
                    # Process anchor at expression end
                    rule = re.sub(r'\\\|$', '$', rule, 1)
                    # Remove leading wildcards
                    rule = re.sub(r'^(?:\.\*)', '', rule, 1)
                    # Remove trailing wildcards
                    rule = re.sub(r'(?:\.\*)$', '', rule, 1)
                if not rule: continue # Invalid
                # Regular expressions
                line = re.sub(r'(?:\(.*?\)\?)|(?:\(.*?\|.*?\))', '()', rule)
                line = re.sub(r'(?:[\w-]+\.?)?(?:\*|\?|\|)(?:[\w-]+)?', '.*', line)
                idot = line.find('\\.')
                if idot == -1:
                    hash_key = None
                else:
                    # Find domain field
                    istart = line.find(':') + 1
                    if istart > idot: istart = 0
                    iend = line.find('\\/', idot+2)
                    if iend == -1: iend = line.find('\\..*', idot+2)
                    if iend == -1: iend = None
                    line = line[istart:iend].replace('\\-', '-')
                    # Remove uncertain field
                    line = re.findall(r'[\w-]{2,}', line)
                    # Try get a hash word
                    try:
                        hash_key = line.pop()
                        if line: hash_key = max(line, key=len)
                    except IndexError:
                        hash_key = None
                if hash_key:
                    if hash_key in hash[rule_type]:
                        hash[rule_type][hash_key].add(rule)
                    else:
                        #noinspection PySetFunctionToLiteral
                        hash[rule_type][hash_key] = set([rule])
                else:
                    regxep[rule_type].add(rule)
            return keyword, hash, regxep

        class jsRegExp(object):
            def __init__(self, r):
                self.r = r
            def __json__(self):
                return '/%s/' % self.r

        def _iterdump(o):
            if isinstance(o, (list, tuple, set, frozenset)):
                yield '['
                i = len(o)
                for v in o:
                    for v in _iterdump(v): yield v
                    i -= 1
                    if i > 0: yield ','
                yield ']'
            elif isinstance(o, dict):
                yield '{'
                i = len(o)
                for k,v in o.iteritems():
                    for k in _iterdump(k): yield k
                    yield ':'
                    for v in _iterdump(v): yield v
                    i -= 1
                    if i > 0: yield ','
                yield '}'
            elif isinstance(o, str):
                yield "'%s'" % o.encode('string-escape')
            elif isinstance(o, unicode):
                yield "'%s'" % o.encode('unicode-escape')
            elif isinstance(o, (int, long, float)):
                yield str(o)
            elif o is True: yield 'true'
            elif o is False: yield 'false'
            elif o is None: yield 'null'
            else:
                yield o.__json__()

        def dump2js(o):
            return ''.join(_iterdump(o))

        def _buildRuleList(rule, callback):
            kw, hh, sh = rule
            for i in xrange(3):
                kw[i] = tuple(kw[i])
                for k,v in hh[i].iteritems():
                    hh[i][k] = tuple([callback(r) for r in v])
                sh[i] = tuple([callback(r) for r in sh[i]])
            return tuple(kw + hh + sh)

        def _makeRuleList(rule, callback):
            rule = _parseRule(rule)
            _merge_regexp(rule)
            return _buildRuleList(rule, callback), _sumRule(rule)

        IP, PORT, fix_address = utils.get_main_address(1)
        def _parseListInput(ilist):
            olist = []; info = []
            for uri in ilist:
                if not uri: continue
                parser = None; proxy = 'default'
                if not isinstance(uri, basestring):
                    if len(uri) > 1:
                        if callable(uri[1]):
                            parser = uri[1]
                            if len(uri) > 2: proxy = uri[2]
                        else:
                            proxy = uri[1]
                            if len(uri) > 2 and callable(uri[2]): parser = uri[2]
                    uri = uri[0]
                if uri.startswith('string://'):
                    proxy = uri
                    uri = (uri[:64] + '...').encode('string-escape')
                elif '://' in uri:
                    if proxy == 'default':
                        proxy = config.global_proxy
                    else:
                        proxy = Proxy(proxy and fix_address(proxy))
                else:
                    proxy = None
                olist.append((uri, proxy, parser))
                info.append(uri)
            return olist, ', '.join(info)

        def _fetchRule(rule, backup, new_backup):
            uri, proxy, parser = rule
            rule, date = new_backup.get(uri, (None, None))
            if rule is None:
                #noinspection PyBroadException
                try:
                    if '://' in uri:
                        url = URLInfo(uri)
                        fp = proxy.get_opener(url, {'keep_alive':False}).open(url)
                        if fp.status == 200:
                            date = fp.msg.getheader('Last-Modified')
                            url = backup.get(uri, (0,0))
                            if date == url[1]:
                                rule = url[0]; parser = None
                            else:
                                rule = fp.read()
                        fp.close()
                    else:
                        url = ospath.join(misc_dir, uri)
                        with open(url, 'rb') as fp:
                            rule = fp.read()
                            date = datetime.utcfromtimestamp(_os.stat(url).st_mtime
                                ).strftime('%a, %d %b %Y %H:%M:%S GMT')
                except:
                    pass
                if rule is None:
                    rule, date = backup.get(uri, ('', 'failed'))
                else:
                    #noinspection PyBroadException
                    try:
                        fp = rule.decode('base64')
                        fp[4:10].decode('ascii')
                        rule = fp
                    except:
                        pass
                    if parser: rule = parser(rule)
                new_backup[uri] = rule, date
            return rule, date

        _config = []
        #noinspection PyUnboundLocalVariable
        def _add_task(i, v):
            if not _config:
                f = (_os.name == 'nt' and config.config.vget(int, 'listen_port', 8086) > 0)
                _config[:] = [], [], [], f
                config.add_task(_init_config)
            _config[i].append(v)

        def _init_config():
            backup = cache_get('pac', {})
            new_backup = {}
            for lists,self in _config[0]:
                self.rulelist = _update_rules(lists, backup, new_backup)
                del self.match
            for lists,self in _config[1]:
                self.iplist = _update_iplist(lists, backup, new_backup)
                del self.match
            for lists,files,default,resolve in _config[2]:
                _update_pac(lists, files, default, resolve, backup, new_backup)
            if not cache_set('pac', new_backup):
                echo('!! Backup rules failed.\n')
            if _config[2] and _config[3]: notify_gui('RELOAD')

        def _RuleList(rulelist, early=False):
            self = RuleList()
            if isinstance(rulelist, basestring):
                self.rulelist, info = _makeRuleList(rulelist, re.compile)
                echo('  RuleList: %s rules from string.\n' % info)
            else:
                self.match = _early_match[bool(early)]
                rulelist, info = _parseListInput(rulelist)
                echo('  RuleList: schedule to load rules from "%s".\n' % info)
                _add_task(0, (rulelist, self))
            return self

        def _IpList(iplist, early=False):
            self = IpList()
            if isinstance(iplist, basestring):
                self.iplist = iplist = _makeIpList(iplist)
                echo('  IpList: %d ip ranges from string.\n' % len(iplist))
            else:
                self.match = _early_match[bool(early)]
                iplist, info = _parseListInput(iplist)
                echo('  IpList: schedule to load ip list from "%s".\n' % info)
                _add_task(1, (iplist, self))
            return self

        def _PacFile(rulelists, iplists, files, default='DIRECT', resolve=True):
            if isinstance(files, basestring):
                files = (files,)
            if not default: default = 'DIRECT'
            if isinstance(default, basestring): default = [default]
            default = (list(default) * 3)[:3]
            lists = []; infos = []
            for ilist,target in rulelists:
                if isinstance(ilist, basestring):
                    ilist = _makeRuleList(ilist, jsRegExp)
                    lists.append((0, ilist, target))
                else:
                    ilist, info = _parseListInput(ilist)
                    lists.append((1, ilist, target))
                    infos.append(info)
            for ilist,target in iplists:
                if isinstance(ilist, basestring):
                    lists.append((2, _makeIpList(ilist), target))
                else:
                    ilist, info = _parseListInput(ilist)
                    lists.append((3, ilist, target))
                    infos.append(info)
            if not infos:
                echo('  PacFile: load rules from string, save to "%s".\n'
                    % ', '.join(files))
                _update_pac(lists, files, default, resolve, {}, {})
            else:
                echo('  PacFile: schedule to load rules from "%s", save to "%s".\n'
                    % (', '.join(infos), ', '.join(files)))
                _add_task(2, (lists, files, default, resolve))

        def _merge_rules(main, sub):
            KW, HH, SH = main
            kw, hh, sh = sub
            for i in xrange(3):
                KW[i] |= kw[i]
                HHi = HH[i]
                for k,v in hh[i].iteritems():
                    if k in HHi:
                        HHi[k] |= v
                    else:
                        HHi[k] = v
                SH[i] |= sh[i]

        def _merge_regexp(rules):
            for rule in rules[1]:
                for k,v in rule.iteritems():
                    if len(v) < 2:
                        rule[k] = list(v); continue
                    nv = []; v = ['(?:%s)'%i for i in v]; left = []
                    while v:
                        try:
                            nv.append(re.compile('|'.join(v)).pattern)
                            v = left; left = []
                        except AssertionError:
                            left = v[-1:] + left; v = v[:-1]
                    rule[k] = nv
            rule = rules[2]
            for k,v in enumerate(rule):
                if len(v) < 2:
                    rule[k] = list(v); continue
                nv = []; v = ['(?:%s)'%i for i in v]; left = []
                while v:
                    try:
                        nv.append(re.compile('|'.join(v)).pattern)
                        v = left; left = []
                    except AssertionError:
                        left = v[-1:] + left; v = v[:-1]
                rule[k] = nv

        def _make_rules(lists, backup, new_backup, callback):
            rules = [set(), set(), set()], [{}, {}, {}], [set(), set(), set()]
            info = []
            for rule in lists:
                uri = rule[0]
                if uri.startswith('string://'):
                    rule, date = rule[1][9:], 'string'
                else:
                    rule, date = _fetchRule(rule, backup, new_backup)
                rule = _parseRule(rule)
                info.append('%s: %s, %s' % (uri, _sumRule(rule), date))
                _merge_rules(rules, rule)
            _merge_regexp(rules)
            info.append('Total: %s' % _sumRule(rules))
            return _buildRuleList(rules, callback), info

        def _update_rules(lists, backup, new_backup):
            lists, info = _make_rules(lists, backup, new_backup, re.compile)
            echo('PAC RuleList result:\n  ' + '\n  '.join(info) + '\n')
            return lists

        def _make_iplist(lists, backup, new_backup):
            rules = []; info = []
            for rule in lists:
                uri = rule[0]
                if uri.startswith('string://'):
                    rule, date = rule[1][9:], 'string'
                else:
                    rule, date = _fetchRule(rule, backup, new_backup)
                rule = _parseIpList(rule)
                info.append('%s: %d ranges, %s' % (uri, len(rule), date))
                rules.extend(rule)
            rules = _buildIpList(rules)
            info.append('Total: %d ranges' % len(rules))
            return rules, info

        def _update_iplist(lists, backup, new_backup):
            lists, info = _make_iplist(lists, backup, new_backup)
            echo('PAC IpList result:\n  ' + '\n  '.join(info) + '\n')
            return lists

        def _update_pac(lists, files, default, resolve, backup, new_backup):
            rules = []; iplist = []
            infos = ['DEFAULT is %s' % default, 'dnsResolve: %s' % ('Yes' if resolve else 'No')]
            for i,lists,target in lists:
                infos.append('Result for "%s":' % target)
                #noinspection PySimplifyBooleanCheck
                if i == 0:
                    rules.append((lists[0], target))
                    infos.append('Total: %s' % lists[1])
                elif i == 1:
                    lists, info = _make_rules(lists, backup, new_backup, jsRegExp)
                    rules.append((lists, target))
                    infos.append('\n// '.join(info))
                elif i == 2:
                    iplist.append((lists, target))
                    infos.append('Total: %d ranges' % len(lists))
                elif i == 3:
                    lists, info = _make_iplist(lists, backup, new_backup)
                    iplist.append((lists, target))
                    infos.append('\n// '.join(info))
            _save_pac(rules, iplist, '// ' + '\n// '.join(infos), files, default, resolve)

        def _save_pac(rules, iplist, info, files, default, resolve):
            resolve = '' if resolve else '&&(ip||host.indexOf(\':\')>=0||/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host))'
            start = ('// AUTO-GENERATED RULES WITH wallproxy BY HustMoon'
                ', DO NOT MODIFY!')
            end = '// END OF AUTO-GENERATED RULES'
            code = '''%s\n%s\nvar FindProxyByRules=(function(){
var listen=''||['%s',%d];
var rules=%s;
var iplists=%s;
var b=listen[0],d=listen[1];0<=b.indexOf(':')&&(b='['+b+']');b=b+':';d=b+d;function p(p){return p.replace('*:*',d).replace('*:',b)}var c=rules.length;while(0<=--c)rules[c][1]=p(rules[c][1]);c=iplists.length;while(0<=--c)iplists[c][1]=p(iplists[c][1]);var k='PROXY '+d+';DIRECT',l=p('%s'),m=p('%s');p=p('%s');var dnsResolve2=(function(){try{var _=dnsResolveEx("localhost");return function(h){return(h=dnsResolveEx(h))?h.split(";",1)[0]:""}}catch(e){try{return dnsResolve}catch(e){return function(h){return dnsResolve(h)}}}})();return function(url,host,ip){if((host=host.toLowerCase())=='wallproxy')return k;var j,i,g,e,c,a,b,f,d,h;url=url.toLowerCase();j='http'==url.split(':',1);i=host.split('.');g=rules.length;a:for(c=0;c<g;c++){e=rules[c][0];for(a=0;3>a;a++){d=e[a];if(j){b=d.length;while(0<=--b)if(0<=url.indexOf(d[b])){if(1!=a)return rules[c][1];continue a}}d=e[a+3];b=i.length;while(0<=--b)if((h=d[i[b]])&&h.constructor==Array){f=h.length;while(0<=--f)if(h[f].test(url)){if(1!=a)return rules[c][1];continue a}}d=e[a+6];b=d.length;while(0<=--b)if(d[b].test(url)){if(1!=a)return rules[c][1];continue a}}}g=iplists.length;if(0<g%s){void 0===ip&&(ip=dnsResolve2(host));if(0<=ip.indexOf(':'))return m;ip=ip.split('.');if(4!=ip.length)return l;ip=(ip[0]<<24|ip[1]<<16|ip[2]<<8|ip[3])>>>0;for(c=0;c<g;c++){e=iplists[c][0];a=0;f=e.length;while(a<f){b=Math.floor((a+f)/2);d=e[b];if(d[0]<=ip&&ip<=d[1])return iplists[c][1];ip<d[0]?f=b:a=b+1}}}return p}})();
%s''' % (start, info, IP, PORT, dump2js(rules), dump2js(iplist), default[2], default[1], default[0], resolve, end)
            template = '''//proxy auto-config
function FindProxyForURL(url, host) {
\tif (/^https?:\/\//i.test(url) && host != '127.0.0.1' && host != 'localhost')
\t\treturn FindProxyByRules(url, host);
\treturn 'DIRECT';
}\n\n%s\n'''
            pattern = re.compile(r'(?ms)^(\s*%s\s*)^.*$(\s*%s\s*)$' % (
                re.escape(start), re.escape(end)))
            echo('Writing PAC to "%s".\n' % ', '.join(files))
            for files in files:
                files = ospath.join(misc_dir, files)
                try:
                    with open(files, 'r') as fp:
                        pac = fp.read().replace('%', '%%')
                except IOError:
                    pac = template
                else:
                    pac, n = pattern.subn(r'\n%s\n', pac)
                    #noinspection PySimplifyBooleanCheck
                    if n==0: pac = template
                with open(files, 'w') as fp:
                    fp.write(pac % code)

        class HostList(object):
            def match(self, host):
                return (host.endswith(self.ends) or
                        any(match(host) for match in self.matches))

        def _HostList(hosts):
            self = HostList()
            hosts = set(hosts.split() if isinstance(hosts, basestring) else hosts)
            self.ends = tuple([k for k in hosts if k.startswith('.')])
            hosts = ['(?:^%s$)' % k.replace('.', '\.').replace('*', '.*')
                     for k in hosts.difference(self.ends)]
            pats = []; left = []
            while hosts:
                try:
                    pats.append(re.compile('|'.join(hosts)))
                    hosts = left; left = []
                except AssertionError:
                    left = hosts[-1:] + left; hosts = hosts[:-1]
            self.matches = tuple([k.match for k in pats])
            return self

        def _makeIpFinder(iplists, default):
            default, ipv6, failed = default
            def findProxyByIpList(host):
                ip = dnsResolve2(host)
                if not ip:
                    return failed
                if ':' in ip:
                    return ipv6
                ip = ip2int(ip)
                for iplist,target in iplists:
                    if iplist.match(ip):
                        return target
                return default
            return findProxyByIpList

        globals().update(
            dnsDomainIs = dnsDomainIs,
            dnsResolve = dnsResolve,
            dnsResolve2 = dnsResolve2,
            ip2int = ip2int,
            IpList = _IpList,
            RuleList = _RuleList,
            PacFile = _PacFile,
            HostList = _HostList,
            makeIpFinder = _makeIpFinder,
        )

    DEBUG_LEAK(pac_plugin)


    class _LazyModuleDesc(object):
        def __init__(self, name, func):
            self.name = name
            self.func = func
        def __get__(self, obj, tp):
            if obj is None: return self
            delattr(tp, self.name)
            return config.install(self.name, self.func)

    class handlers(object):
        def __init__(self, **kw):
            self.utils = utils
            for name,func in kw.iteritems():
                setattr(handlers, name, _LazyModuleDesc(name, func))

        def setup(self):
            def import_from(mod):
                try:
                    names = find_assign_names()
                except KeyError:
                    raise SyntaxError('invalid syntax for `import_from(mod)`')
                if isinstance(mod, basestring):
                    mod = getattr(self, mod)
                if len(names) == 1:
                    return getattr(mod, names[0])
                return [getattr(mod, name) for name in names]
            config.import_from = import_from

            def install(name, func):
                if callable(func):
                    mod = new_module(name, config=config, utils=utils, data={})
                    mod.module = mod
                    try:
                        env_run(func, mod.__dict__)
                    finally:
                        if getattr(mod, 'module', None) is mod:
                            del mod.module
                    setattr(self, name, mod)
                return getattr(self, name)
            config.install = install

            def use(mod, *names):
                if isinstance(mod, basestring):
                    mod = getattr(self, mod)
                if '*' in names:
                    if hasattr(mod, '__all__'):
                        names = mod.__all__
                    else:
                        names = [n for n in mod.__dict__ if not n.startswith('_')]
                if names:
                    env = sys._getframe(1).f_globals
                    for name in names:
                        env[name] = getattr(mod, name)
                return mod
            config.use = use

        def clean(self):
            self.__dict__.clear()
            utils.__dict__.clear()
            #noinspection PyMethodFirstArgAssignment
            self = config.__dict__
            self.pop('import_from', None)
            self.pop('install', None)
            self.pop('use', None)

    handlers = handlers(util=util_plugin, pac=pac_plugin)

if __name__ == '__main__':
    def main():
        from os.path import basename, splitext
        mod = __import__(splitext(basename(__file__))[0])
        return mod.main
    main = main()

main()
