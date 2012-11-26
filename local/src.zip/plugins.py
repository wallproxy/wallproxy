from __future__ import with_statement
def paas():
    print 'Initializing PAAS for proxy based on cloud service.'
    class _6(object):
        (set_hosts, Forward,) = config.import_from('util')
        (HeaderDict, Proxy, URLInfo, unparse_netloc, del_bad_hosts,) = config.import_from(utils)
        v = (set_hosts, Forward, HeaderDict, Proxy, URLInfo, unparse_netloc,
         del_bad_hosts)
    (___________, _11, __, _10, ____, ________, _______________,) = _6.v
    import re as _0
    import zlib as ___
    import socket as _9
    import struct as _________
    import time as _____
    import random as _5
    import threading as _1
    from binascii import a2b_hex as ___________________, b2a_hex as _2
    from base64 import b64encode as _8
    try:
        import ssl as ______________
    except ImportError:
        ______________ = None
    class __________________(Exception):
        def __init__(_________, __, _____):
            _________.code = __
            _________.msg = _____

        def __str__(__):
            return ('HTTP Error %s: %s' % (__.code, __.msg))

    ____________ = _0.compile('(\\d+)?-(\\d+)?')
    _12 = _0.compile('bytes\\s+(\\d+)-(\\d+)/(\\d+)')
    def ____________________(__________, ____):
        ___ = __________.get('Range', '')
        _______ = ____________.search(___)
        if _______:
            _______ = _______.groups()
            if _______[0]:
                ____ -= 1
                if _______[1]:
                    _______ = (2, int(_______[0]), int(_______[1]))
                    if ((_______[2] - _______[1]) > ____):
                        ___ = ('bytes=%d-%d' % (_______[1], (_______[1] + ____)))
                else:
                    _______ = (0, int(_______[0]))
                    ___ = ('bytes=%d-%d' % (_______[1], (_______[1] + ____)))
            elif _______[1]:
                _______ = (1, int(_______[1]))
                if (_______[1] > ____):
                    ___ = 'bytes=-1024'
            else:
                _______ = (None,)
                ___ = ('bytes=0-%d' % (____ - 1))
        else:
            _______ = (None,)
            ___ = ('bytes=0-%d' % (____ - 1))
        return (_______, ___)

    _____________ = _0.compile(', ([^ =]+(?:=|$))')
    def _7(__________):
        ______ = __________.get('Set-Cookie')
        if ______:
            __________['Set-Cookie'] = _____________.sub('\\r\\nSet-Cookie: \\1', ______)
        return __________

    def _4(**_____):
        ____________ = _______
        ___ = _____.get('appids', '')
        ____________.appids = ___ = (___.split() if isinstance(___, str) else list(___))
        if not ___:
            raise ValueError('no appids specified')
        ______ = _____.get('scheme', 'http').lower()
        if (______ not in ('http', 'https')):
            raise ValueError(('invalid scheme: ' + ______))
        ____________.url = ____(('%s://%s.appspot.com%s?' % (______, ____________.appids[0], _____.get('path', '/fetch.py'))))
        ____________.password = _____.get('password', '')
        ___ = _____.get('proxy', 'default')
        ____________.proxy = (config.global_proxy if (___ == 'default') else _10(___))
        ___ = _____.get('hosts')
        if ___:
            ___ = (___.split() if isinstance(___, str) else list(___))
        if not ___:
            ___ = 'eJxdztsNgDAMQ9GNIvIoSXZjeApSqc3nUVT3ZojakFTR47wSNEhB8qXhorXg+kMjckGtQM9efDKf91Km4W+N4M1CldNIYMu+qSVoTm7MsG5E4KPd8apInNUUMo4betRQjg=='.decode('base64').decode('zlib').split('|')
        ___________('.appspot.com', ___, 0)
        if ____________.proxy.value:
            ____________.hosts = ___
            ____________.proxy = ____________.proxy.new_hosts((___[0], ____________.url.port))
        ____________.headers = __(_____.get('headers', 'Content-Type: application/octet-stream'))
        ___ = _____.get('max_threads', 0)
        ____________.max_threads = min((10 if (___ <= 0) else ___), len(____________.appids))
        ____________.bufsize = _____.get('bufsize', 8192)
        ____________.maxsize = _____.get('maxsize', 1000000)
        ____________.waitsize = _____.get('waitsize', 500000)
        assert (____________.bufsize <= ____________.waitsize <= ____________.maxsize)
        ____________.local_times = _____.get('local_times', 3)
        ____________.server_times = _____.get('server_times')
        ____________.fetch_mode = _____.get('fetch_mode', 0)
        ____________.fetch_args = _____.get('fetch_args', {})
        print ('  Init GAE with appids: %s' % '|'.join(____________.appids))
        print ('  max_threads when range fetch: %d' % ____________.max_threads)
        ___ = _____.get('listen')
        if ___:
            def ______________(__):
                if __.proxy_type.endswith('http'):
                    return ____________

            ___ = data['GAE_server'] = utils.start_new_server(___, ______________)
            print ('  GAE listen on: %s' % ________(___.server_address[:2]))
        return ____________

    class _________________(object):
        skip_headers = frozenset(['Proxy-Connection', 'Content-Length', 'Host', 'Vary', 'Via',
         'X-Forwarded-For', 'X-ProxyUser-IP'])
        def build_params(__________, ______, ____):
            _______ = ______.command
            _________ = ______.headers
            if (_______ == 'GET'):
                (______.rangeinfo, _____________,) = ____________________(_________, __________.maxsize)
                if (____ or (______.rangeinfo[0] == 0)):
                    _________['Range'] = _____________
            else:
                (______.rangeinfo, _____________,) = ((None,), '')
            ____________ = __________.skip_headers
            _________.data = dict((_________ for _________ in _________.iteritems() if (_________[0] not in ____________)))
            __ = {'url': ______.url,
             'method': _______,
             'headers': _________,
             'payload': ______.read_body()}
            if _____________:
                __['range'] = _____________
            if __________.password:
                __['password'] = __________.password
            if __________.server_times:
                __['fetchmax'] = __________.server_times
            return (__, dict(__________.fetch_args, proxy_auth=______.userid))

        def fetch(_3, (_10, ______________,), server=None):
            _10 = ___.compress('&'.join([('%s=%s' % (_________________, _2(str(______)))) for (_________________, ______,) in _10.iteritems()]), 9)
            _4 = []
            _8 = (server or _3.url)
            _____ = _3.proxy.get_opener(_8, ______________)
            ___________ = _12 = 0
            __________ = _3.local_times
            ________________ = len(_3.appids)
            while ((___________ < __________) and (_12 < ________________)):
                _____________ = 0
                try:
                    _1 = _____.open(_8, _10, 'POST', _3.headers, 0)
                    if (_1.status != 200):
                        _1.close()
                        raise __________________(_1.status, _1.reason)
                except Exception, _7:
                    _____.close()
                    if isinstance(_7, __________________):
                        _4.append(str(_7))
                        if (_7.code == 503):
                            ___________ -= 1
                            if server:
                                _8 = _3.url
                                server.__init__(_8)
                                server = None
                            else:
                                _12 += 1
                                _3.appids.append(_3.appids.pop(0))
                                _____________ |= 1
                                _8.hostname = ('%s.appspot.com' % _3.appids[0])
                                print ('GAE: switch appid to %s' % _3.appids[0])
                        elif (_7.code == 404):
                            if _3.proxy.value:
                                _3.hosts.append(_3.hosts.pop(0))
                                _____________ |= 2
                                print ('GAE: switch host to %s' % _3.hosts[0])
                            else:
                                _______________()
                        elif (_7.code == 502):
                            if (_8.scheme != 'https'):
                                ___________ -= 1
                                _8.scheme = 'https'
                                _8.port = 443
                                _____________ |= 3
                                print 'GAE: switch scheme to https'
                    elif isinstance(_7, _9.error):
                        _________________ = _7.args[0]
                        if ((_8.scheme != 'https') and (_________________ in (10054, 54, 20054))):
                            ___________ -= 1
                            _8.scheme = 'https'
                            _8.port = 443
                            _____________ |= 3
                            print 'GAE: switch scheme to https'
                        elif _3.proxy.value:
                            _4.append(('Connect other proxy failed: %s' % _7))
                            _3.hosts.append(_3.hosts.pop(0))
                            _____________ |= 2
                            print ('GAE: switch host to %s' % _3.hosts[0])
                        else:
                            _4.append(('Connect fetchserver failed: %s' % _7))
                            if (_______________() and (_________________ in (10054, 54, 20054, 10047))):
                                ___________ -= 1
                    else:
                        _4.append(('Connect fetchserver failed: %s' % _7))
                    if (_____________ & 1):
                        _8.rebuild()
                    if (_____________ & 2):
                        if _3.proxy.value:
                            _3.proxy = _3.proxy.new_hosts((_3.hosts[0], _8.port))
                        _____ = _3.proxy.get_opener(_8, ______________)
                else:
                    try:
                        _____________ = _1.read(1)
                        if (_____________ == '0'):
                            (_______, _5, _6,) = _________.unpack('>3I', _1.read(12))
                            ____________ = __([(_________________, ___________________(______)) for (_________________, _0, ______,) in (_________.partition('=') for _________ in _1.read(_5).split('&'))])
                            if ((_3.fetch_mode == 1) or ((_______ == 206) and (_3.fetch_mode == 2))):
                                _1 = _1.read()
                        elif (_____________ == '1'):
                            _13 = ___.decompress(_1.read())
                            _1.close()
                            (_______, _5, _6,) = _________.unpack('>3I', _13[:12])
                            ____________ = __([(_________________, ___________________(______)) for (_________________, _0, ______,) in (__.partition('=') for __ in _13[12:(12 + _5)].split('&'))])
                            _1 = _13[(12 + _5):((12 + _5) + _6)]
                        else:
                            raise ValueError(('Data format not match(%s)' % _8))
                        ____________.setdefault('Content-Length', str(_6))
                        return (0, (_______, ____________, _1))
                    except Exception, _7:
                        _4.append(str(_7))
                ___________ += 1
            return ((-1), _4)

        def write_content(___, __________, _____, first=False):
            ______ = __________.socket.sendall
            if isinstance(_____, str):
                ______(_____)
            else:
                _________ = ___.bufsize
                _______ = _____.read((___.waitsize if first else _________))
                while _______:
                    ______(_______)
                    _______ = _____.read(_________)
                _____.close()

        def need_range_fetch(_______, ____________, ______________, ___):
            ____ = _12.search(______________.get('Content-Range', ''))
            if not ____:
                return
            ____ = map(int, ____.groups())
            ___________ = ____________.rangeinfo
            _____________ = ___________[0]
            if (_____________ is None):
                _________ = 0
                _____ = ____[2]
                _________________ = 200
                del ______________['Content-Range']
            else:
                if (_____________ == 0):
                    _________ = ___________[1]
                    _____ = ____[2]
                elif (_____________ == 1):
                    _________ = (____[2] - ___________[1])
                    _____ = ____[2]
                else:
                    _________ = ___________[1]
                    _____ = (___________[2] + 1)
                _________________ = 206
                ______________['Content-Range'] = ('bytes %d-%d/%d' % (_________, (_____ - 1), ____[2]))
            ______________['Content-Length'] = str((_____ - _________))
            ____________.start_response(_________________, _7(______________))
            if (_________ == ____[0]):
                return [_________, _____, (____[1] + 1), ___]
            return [_________, _____, _________, None]

        def range_fetch(_______, _____________, ______, ____________):
            ______[0].pop('range', None)
            ________ = (____________[1] - ____________[0])
            if ((_______.max_threads > 1) and ((____________[1] - ____________[2]) > _______.maxsize)):
                _________ = _______._thread_range
            else:
                _________ = _______._single_range
            ___________ = _____.time()
            if _________(_____________, ______, ____________):
                ___________ = ((________ / 1000.0) / ((_____.time() - ___________) or 0.0001))
                print ('>>>>>>>>>> Range Fetch ended (all @ %sKB/s)' % ___________)
            else:
                _____________.close_connection = True
                print '>>>>>>>>>> Range Fetch failed'

        def _single_range(_________, __________, ____, ____________):
            (___________________, _____________, __, ___,) = ____________
            del ____________[:]
            _____________ -= 1
            ____________________ = _________.maxsize
            _________________ = 0
            ________ = ____[0]['headers']
            print ('>>>>>>>>>> Range Fetch started%s: bytes=%d-%d, step=%d' % (__________.proxy_host, ___________________, _____________,
             ____________________))
            if ___:
                _________.write_content(__________, ___, True)
            while (__ <= _____________):
                if (_________________ > 16):
                    return False
                ________['Range'] = ('bytes=%d-%d' % (__, min((__ + ____________________), _____________)))
                (_______, ____________,) = _________.fetch(____)
                if (_______ != (-1)):
                    (______, ___________, ___,) = ____________
                    _______________ = _12.search(___________.get('Content-Range', ''))
                if ((_______ == (-1)) or (______ >= 400)):
                    _________________ += 1
                    ________________ = _5.randint((2 * _________________), (2 * (_________________ + 1)))
                    _____.sleep(________________)
                elif ('Location' in ___________):
                    _________________ += 1
                    ____[0]['url'] = ___________['Location']
                elif not _______________:
                    _________________ += 1
                else:
                    print ('>>>>>>>>>> %s' % ___________['Content-Range'])
                    _________________ = 0
                    _________.write_content(__________, ___)
                    __ = (int(_______________.group(2)) + 1)
            return True

        def _thread_range(______, ___, _____________, ________________):
            (______________, ________, ________________, ____,) = ______._start_thread_range(___, _____________, ________________)
            ____________ = 0
            while (____________ < ________):
                if ________________[1]:
                    print ('>>>>>>>>>> failed@%d bytes=%d-%d' % tuple(________________[1][2:5]))
                    return False
                _______________ = ______________[____________]
                if not isinstance(_______________[0], int):
                    if _______________[0]:
                        ____(_______________[0], _______________)
                    ____________ += 1
                    continue
                _____.sleep(0.001)
            return True

        def _start_thread_range(_______, ________, ___________________, _______________):
            (______, ____________________, _____________, ________________,) = _______________
            del _______________[:]
            ______________ = _______.maxsize
            _0 = (______________ - 1)
            ___ = []
            ____ = 1
            while (_____________ < ____________________):
                ___.append([0, set(), ____, _____________, (_____________ + _0)])
                _____________ += ______________
                ____ += 1
            ____________________ -= 1
            ___[(-1)][(-1)] = ____________________
            __________ = len(___)
            _________ = min(__________, _______.max_threads)
            __ = _1.Lock()
            __________________ = _1.Lock()
            _______________ = [1, None, _________]
            def _____(____, ________________):
                try:
                    ______________ = None
                    if ((_______________[0] != ________________[2]) or not __________________.acquire(0)):
                        ______________ = []
                        __________ = ____.read(8192)
                        while __________:
                            ______________.append(__________)
                            if ((_______________[0] == ________________[2]) and __________________.acquire(0)):
                                break
                            __________ = ____.read(8192)
                        else:
                            ____.close()
                            __.acquire()
                            ________________[0] = ''.join(______________)
                            __.release()
                            return
                    try:
                        _______________[0] += 1
                        print ('>>>>>>>>>> block=%d bytes=%d-%d' % tuple(________________[2:5]))
                        if ______________:
                            ________.socket.sendall(''.join(______________))
                        _______.write_content(________, ____)
                        ________________[0] = None
                    finally:
                        __________________.release()
                except:
                    __.acquire()
                    del ___[:]
                    _______________[1] = ________________
                    __.release()

            _________________ = _______.appids[1:]
            _5.shuffle(_________________)
            _________________.append(_______.appids[0])
            _________________ = _________________[:_________]
            print ('>>>>>>>>>> Range Fetch started: threads=%d blocks=%d bytes=%d-%d appids=%s' % (_________, __________, ______, ____________________,
             '|'.join(_________________)))
            ______ = (0, (), 0, ______, (___[0][3] - 1))
            try:
                with __________________:
                    for ____ in xrange(_________):
                        _0 = _1.Thread(target=_______._range_thread, args=(_________________[____], ___________________, ___, __,
                         _______________, _____))
                        _0.setDaemon(True)
                        _0.start()
                    if ________________:
                        print ('>>>>>>>>>> block=%d bytes=%d-%d' % ______[2:5])
                        _______.write_content(________, ________________, True)
            except:
                __.acquire()
                del ___[:]
                _______________[1] = ______
                __.release()
            return (___, __________, _______________, _____)

        def _range_thread(________________, _________________, ______________, _______, _____________, _____, _________):
            _________________ = ____(________________.url, hostname=('%s.appspot.com' % _________________))
            ______ = ______________[0].copy()
            ______['headers'] = ____________ = __(______['headers'])
            ______________ = (______, ______________[1])
            ______ = _1.current_thread()
            while 1:
                with _____________:
                    try:
                        for ___________ in _______:
                            if (___________[0] == 0):
                                ________ = ___________[1]
                                if (len(________) == _____[2]):
                                    ________.clear()
                                if (______ not in ________):
                                    ___________[0] = 1
                                    break
                        else:
                            for ___________ in _______:
                                ___________[1].discard(______)
                            _____[2] -= 1
                            raise StopIteration('No task for me')
                    except StopIteration:
                        break
                ____________['Range'] = ('bytes=%d-%d' % (___________[3], ___________[4]))
                while 1:
                    if not _______:
                        return
                    (____________________, ___,) = ________________.fetch(______________, _________________)
                    if not _______:
                        return
                    if ((____________________ != (-1)) and (___[0] == 206)):
                        ___ = ___[2]
                        if isinstance(___, str):
                            _____________.acquire()
                            ___________[0] = ___
                            _____________.release()
                        else:
                            _________(___, ___________)
                        break
                    with _____________:
                        if (___________[0] >= 2):
                            ________.add(______)
                            ___________[0] = 0
                            break
                        ___________[0] += 1

        def __call__(___, __, force_range=False):
            __.handler_name = 'GAE'
            ___________ = ___.build_params(__, force_range)
            (______, _______,) = ___.fetch(___________)
            if (______ == (-1)):
                return __.send_error(502, str(_______))
            (_________, _____, _____________,) = _______
            if ((_________ == 206) and (__.command == 'GET')):
                _______ = ___.need_range_fetch(__, _____, _____________)
                if _______:
                    del _________
                    del _____
                    del _____________
                    return ___.range_fetch(__, ___________, _______)
            __.start_response(_________, _7(_____))
            ___.write_content(__, _____________)

    _______ = _________________()
    def _3(**__________):
        _____ = ______()
        _____.url = _____________ = ____(__________['url'])
        _____.password = __________.get('password', '')
        _________ = __________.get('proxy', 'default')
        _____.proxy = (config.global_proxy if (_________ == 'default') else _10(_________))
        _____.hosts = None
        _________ = __________.get('hosts')
        if _________:
            _________ = (_________.split() if isinstance(_________, str) else list(_________))
            if _____.proxy.value:
                if (len(_________) > 1):
                    _____.hosts = _________
                _____.proxy = _____.proxy.new_hosts((_________[0], _____________.port))
            else:
                ___________(_____________.hostname, _________, 0)
        _____.headers = __(__________.get('headers', 'Content-Type: application/octet-stream'))
        _____.fetch_args = __________.get('fetch_args', {})
        print ('  Init PAAS with url: %s' % _____________)
        _________ = __________.get('listen')
        if _________:
            def _______________(____):
                if ____.proxy_type.endswith('http'):
                    return _____

            _________ = data['PAAS_server'] = utils.start_new_server(_________, _______________)
            print ('  PAAS listen on: %s' % ________(_________.server_address[:2]))
        return _____

    class ______(object):
        def __call__(_______, ________):
            ________.handler_name = 'PAAS'
            __ = {'method': ________.command,
             'url': ________.url,
             'headers': ________.headers}
            if _______.password:
                __['password'] = _______.password
            __ = '&'.join([('%s=%s' % (_______________, _2(str(__________________)))) for (_______________, __________________,) in __.iteritems()])
            _______.headers['Cookie'] = _8(___.compress(__, 9))
            ___________ = _______.url
            try:
                _____ = _______.proxy.get_opener(___________, dict(_______.fetch_args, proxy_auth=________.userid)).open(___________, ________.read_body(), 'POST', _______.headers, 0)
            except Exception, _________:
                if _______.hosts:
                    _______.hosts.append(_______.hosts.pop(0))
                    print ('PAAS: switch host to %s' % _______.hosts[0])
                    _______.proxy = _______.proxy.new_hosts((_______.hosts[0], ___________.port))
                    return ________.send_error(502, ('Connect other proxy failed: %s' % _________))
                return ________.send_error(502, ('Connect fetchserver failed: %s' % _________))
            ________.start_response(_____.status, _7(_____.msg), _____.reason)
            ______ = ________.socket.sendall
            ____ = _____.read(8192)
            while ____:
                ______(____)
                ____ = _____.read(8192)
            _____.close()

    def __________(**______________):
        __________ = ________________()
        _______________ = ____(______________['url'])
        __________.scheme = _______________.scheme
        __________.host = _______________.host
        __________.path = _______________.path
        _____ = ______________.get('password')
        __________.auth = (_____ if (_____ is None) else ('', _____))
        _____ = ______________.get('proxy', 'default')
        __________.proxy = (config.global_proxy if (_____ == 'default') else _10(_____))
        if ((__________.scheme == 'https') and __________.proxy.https_mode):
            __________.proxy = __________.proxy.https_mode
        __________.value = __________.hosts = None
        _____ = ______________.get('hosts')
        if _____:
            _____ = (_____.split() if isinstance(_____, str) else list(_____))
            if __________.proxy.value:
                if (len(_____) > 1):
                    __________.hosts = _____
                __________.value = [_____[0], _______________.port]
            else:
                ___________(_______________.hostname, _____, 0)
        if not __________.value:
            __________.value = (_______________.hostname, _______________.port)
        print ('  Init SOCKS5 with url: %s' % _______________)
        __________ = _11(__________)
        __________.handler_name = 'SOCKS5'
        _____ = ______________.get('listen')
        if _____:
            _____ = data['SOCKS5_server'] = utils.start_new_server(_____, (lambda ___: __________))
            print ('  SOCKS5 listen on: %s' % ________(_____.server_address[:2]))
        return __________

    class ________________(_10):
        __new__ = object.__new__
        def connect(_________, _______, _____, cmd=1):
            try:
                __________ = _________.proxy.connect(_________.value, _____, 1)
            except Exception:
                if _________.hosts:
                    _________.hosts.append(_________.hosts.pop(0))
                    print ('SOCKS5: switch host to %s' % _________.hosts[0])
                    _________.value[0] = _________.hosts[0]
                raise 
            if (_________.scheme == 'https'):
                try:
                    __________ = ______________.wrap_socket(__________)
                except Exception, ____:
                    raise _9.error(____)
            __________.sendall(('PUT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n' % (_________.path, _________.host)))
            _______ = _________.handlers['socks5'](__________, __________.makefile('rb', 0), _________.auth, 0, _______, cmd)
            return _________._proxysocket(__________, _______)

    globals().update(GAE=_4, PAAS=_3, SOCKS5=__________)

