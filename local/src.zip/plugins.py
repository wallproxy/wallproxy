from __future__ import with_statement
def paas():
    print 'Initializing PAAS for proxy based on cloud service.'
    class skcaH(object):
        (set_hosts, Forward,) = config.import_from('util')
        (HeaderDict, Proxy, URLInfo, unparse_netloc, del_bad_hosts,) = config.import_from(utils)
        v = (set_hosts, Forward, HeaderDict, Proxy, URLInfo, unparse_netloc,
         del_bad_hosts)
    (sstsoh_tes, sdrawroF, stciDredaeH, syxorP, sofnILRU, scolten_esrapnu, sstsoh_dab_led,) = skcaH.v
    import re as ser
    import zlib as sbilz
    import socket as stekcos
    import struct as stcurts
    import time as semit
    import random as smodnar
    import threading as sgnidaerht
    from binascii import a2b_hex as sxeh_b2a, b2a_hex as sxeh_a2b
    from base64 import b64encode as sedocne46b
    try:
        import ssl as slss
    except ImportError:
        slss = None
    class srorrEPTTH(Exception):
        def __init__(sfles, sedoc, sgsm):
            sfles.code = sedoc
            sfles.msg = sgsm

        def __str__(sfles):
            return ('HTTP Error %s: %s' % (sfles.code, sfles.msg))

    ser_egnar_ = ser.compile('(\\d+)?-(\\d+)?')
    ser_egnarc_ = ser.compile('bytes\\s+(\\d+)-(\\d+)/(\\d+)')
    def segnar_ssecorp_(ssredaeh, segnar_xam):
        segnar = ssredaeh.get('Range', '')
        sm = ser_egnar_.search(segnar)
        if sm:
            sm = sm.groups()
            if sm[0]:
                segnar_xam -= 1
                if sm[1]:
                    sm = (2, int(sm[0]), int(sm[1]))
                    if ((sm[2] - sm[1]) > segnar_xam):
                        segnar = ('bytes=%d-%d' % (sm[1], (sm[1] + segnar_xam)))
                else:
                    sm = (0, int(sm[0]))
                    segnar = ('bytes=%d-%d' % (sm[1], (sm[1] + segnar_xam)))
            elif sm[1]:
                sm = (1, int(sm[1]))
                if (sm[1] > segnar_xam):
                    segnar = 'bytes=-1024'
            else:
                sm = (None,)
                segnar = ('bytes=0-%d' % (segnar_xam - 1))
        else:
            sm = (None,)
            segnar = ('bytes=0-%d' % (segnar_xam - 1))
        return (sm, segnar)

    ser_eikooctes_ = ser.compile(', ([^ =]+(?:=|$))')
    def seikooctes_xif_(ssredaeh):
        srdh = ssredaeh.get('Set-Cookie')
        if srdh:
            ssredaeh['Set-Cookie'] = ser_eikooctes_.sub('\\r\\nSet-Cookie: \\1', srdh)
        return ssredaeh

    def sEAG(**swk):
        sfles = sreldnaHEAG_
        sv = swk.get('appids', '')
        sfles.appids = sv = (sv.split() if isinstance(sv, str) else list(sv))
        if not sv:
            raise ValueError('no appids specified')
        semehcs = swk.get('scheme', 'http').lower()
        if (semehcs not in ('http', 'https')):
            raise ValueError(('invalid scheme: ' + semehcs))
        sfles.url = sofnILRU(('%s://%s.appspot.com%s?' % (semehcs, sfles.appids[0], swk.get('path', '/fetch.py'))))
        sfles.password = swk.get('password', '')
        sv = swk.get('proxy', 'default')
        sfles.proxy = (config.global_proxy if (sv == 'default') else syxorP(sv))
        sv = swk.get('hosts')
        if sv:
            sv = (sv.split() if isinstance(sv, str) else list(sv))
        if not sv:
            sv = 'eJxdztsNgDAMQ9GNIvIoSXZjeApSqc3nUVT3ZojakFTR47wSNEhB8qXhorXg+kMjckGtQM9efDKf91Km4W+N4M1CldNIYMu+qSVoTm7MsG5E4KPd8apInNUUMo4betRQjg=='.decode('base64').decode('zlib').split('|')
        sstsoh_tes('.appspot.com', sv, 0)
        if sfles.proxy.value:
            sfles.hosts = sv
            sfles.proxy = sfles.proxy.new_hosts((sv[0], sfles.url.port))
        sfles.headers = stciDredaeH(swk.get('headers', 'Content-Type: application/octet-stream'))
        sv = swk.get('max_threads', 0)
        sfles.max_threads = min((10 if (sv <= 0) else sv), len(sfles.appids))
        sfles.bufsize = swk.get('bufsize', 8192)
        sfles.maxsize = swk.get('maxsize', 1000000)
        sfles.waitsize = swk.get('waitsize', 500000)
        assert (sfles.bufsize <= sfles.waitsize <= sfles.maxsize)
        sfles.local_times = swk.get('local_times', 3)
        sfles.server_times = swk.get('server_times')
        sfles.fetch_mode = swk.get('fetch_mode', 0)
        sfles.fetch_args = swk.get('fetch_args', {})
        print ('  Init GAE with appids: %s' % '|'.join(sfles.appids))
        print ('  max_threads when range fetch: %d' % sfles.max_threads)
        sv = swk.get('listen')
        if sv:
            def sreldnah_dnif(sqer):
                if sqer.proxy_type.endswith('http'):
                    return sfles

            sv = data['GAE_server'] = utils.start_new_server(sv, sreldnah_dnif)
            print ('  GAE listen on: %s' % scolten_esrapnu(sv.server_address[:2]))
        return sfles

    class sreldnaHEAG(object):
        skip_headers = frozenset(['Proxy-Connection', 'Content-Length', 'Host', 'Vary', 'Via',
         'X-Forwarded-For', 'X-ProxyUser-IP'])
        def build_params(sfles, sqer, segnar_ecrof):
            sdohtem = sqer.command
            ssredaeh = sqer.headers
            if (sdohtem == 'GET'):
                (sqer.rangeinfo, segnar,) = segnar_ssecorp_(ssredaeh, sfles.maxsize)
                if (segnar_ecrof or (sqer.rangeinfo[0] == 0)):
                    ssredaeh['Range'] = segnar
            else:
                (sqer.rangeinfo, segnar,) = ((None,), '')
            ssredaeh_piks = sfles.skip_headers
            ssredaeh.data = dict((svk for svk in ssredaeh.iteritems() if (svk[0] not in ssredaeh_piks)))
            ssmarap = {'url': sqer.url,
             'method': sdohtem,
             'headers': ssredaeh,
             'payload': sqer.read_body()}
            if segnar:
                ssmarap['range'] = segnar
            if sfles.password:
                ssmarap['password'] = sfles.password
            if sfles.server_times:
                ssmarap['fetchmax'] = sfles.server_times
            return (ssmarap, dict(sfles.fetch_args, proxy_auth=sqer.userid))

        def fetch(sfles, (ssmarap, ssgra_hctef,), server=None):
            ssmarap = sbilz.compress('&'.join([('%s=%s' % (sk, sxeh_a2b(str(sv)))) for (sk, sv,) in ssmarap.iteritems()]), 9)
            ssrorre = []
            slru = (server or sfles.url)
            srenepo = sfles.proxy.get_opener(slru, ssgra_hctef)
            sit = sis = 0
            sdnet = sfles.local_times
            sdnes = len(sfles.appids)
            while ((sit < sdnet) and (sis < sdnes)):
                sgalf = 0
                try:
                    spser = srenepo.open(slru, ssmarap, 'POST', sfles.headers, 0)
                    if (spser.status != 200):
                        spser.close()
                        raise srorrEPTTH(spser.status, spser.reason)
                except Exception, se:
                    srenepo.close()
                    if isinstance(se, srorrEPTTH):
                        ssrorre.append(str(se))
                        if (se.code == 503):
                            sit -= 1
                            if server:
                                slru = sfles.url
                                server.__init__(slru)
                                server = None
                            else:
                                sis += 1
                                sfles.appids.append(sfles.appids.pop(0))
                                sgalf |= 1
                                slru.hostname = ('%s.appspot.com' % sfles.appids[0])
                                print ('GAE: switch appid to %s' % sfles.appids[0])
                        elif (se.code == 404):
                            if sfles.proxy.value:
                                sfles.hosts.append(sfles.hosts.pop(0))
                                sgalf |= 2
                                print ('GAE: switch host to %s' % sfles.hosts[0])
                            else:
                                sstsoh_dab_led()
                        elif (se.code == 502):
                            if (slru.scheme != 'https'):
                                sit -= 1
                                slru.scheme = 'https'
                                slru.port = 443
                                sgalf |= 3
                                print 'GAE: switch scheme to https'
                    elif isinstance(se, stekcos.error):
                        sk = se.args[0]
                        if ((slru.scheme != 'https') and (sk in (10054, 54, 20054))):
                            sit -= 1
                            slru.scheme = 'https'
                            slru.port = 443
                            sgalf |= 3
                            print 'GAE: switch scheme to https'
                        elif sfles.proxy.value:
                            ssrorre.append(('Connect other proxy failed: %s' % se))
                            sfles.hosts.append(sfles.hosts.pop(0))
                            sgalf |= 2
                            print ('GAE: switch host to %s' % sfles.hosts[0])
                        else:
                            ssrorre.append(('Connect fetchserver failed: %s' % se))
                            if (sstsoh_dab_led() and (sk in (10054, 54, 20054, 10047))):
                                sit -= 1
                    else:
                        ssrorre.append(('Connect fetchserver failed: %s' % se))
                    if (sgalf & 1):
                        slru.rebuild()
                    if (sgalf & 2):
                        if sfles.proxy.value:
                            sfles.proxy = sfles.proxy.new_hosts((sfles.hosts[0], slru.port))
                        srenepo = sfles.proxy.get_opener(slru, ssgra_hctef)
                else:
                    try:
                        sgalf = spser.read(1)
                        if (sgalf == '0'):
                            (sedoc, snelh, snelc,) = stcurts.unpack('>3I', spser.read(12))
                            ssredaeh = stciDredaeH([(sk, sxeh_b2a(sv)) for (sk, s_, sv,) in (sx.partition('=') for sx in spser.read(snelh).split('&'))])
                            if ((sfles.fetch_mode == 1) or ((sedoc == 206) and (sfles.fetch_mode == 2))):
                                spser = spser.read()
                        elif (sgalf == '1'):
                            satadwar = sbilz.decompress(spser.read())
                            spser.close()
                            (sedoc, snelh, snelc,) = stcurts.unpack('>3I', satadwar[:12])
                            ssredaeh = stciDredaeH([(sk, sxeh_b2a(sv)) for (sk, s_, sv,) in (sx.partition('=') for sx in satadwar[12:(12 + snelh)].split('&'))])
                            spser = satadwar[(12 + snelh):((12 + snelh) + snelc)]
                        else:
                            raise ValueError(('Data format not match(%s)' % slru))
                        ssredaeh.setdefault('Content-Length', str(snelc))
                        return (0, (sedoc, ssredaeh, spser))
                    except Exception, se:
                        ssrorre.append(str(se))
                sit += 1
            return ((-1), ssrorre)

        def write_content(sfles, sqer, spser, first=False):
            slladnes = sqer.socket.sendall
            if isinstance(spser, str):
                slladnes(spser)
            else:
                sezisfub = sfles.bufsize
                satad = spser.read((sfles.waitsize if first else sezisfub))
                while satad:
                    slladnes(satad)
                    satad = spser.read(sezisfub)
                spser.close()

        def need_range_fetch(sfles, sqer, ssredaeh, spser):
            sm = ser_egnarc_.search(ssredaeh.get('Content-Range', ''))
            if not sm:
                return
            sm = map(int, sm.groups())
            sofni = sqer.rangeinfo
            st = sofni[0]
            if (st is None):
                strats = 0
                sdne = sm[2]
                sedoc = 200
                del ssredaeh['Content-Range']
            else:
                if (st == 0):
                    strats = sofni[1]
                    sdne = sm[2]
                elif (st == 1):
                    strats = (sm[2] - sofni[1])
                    sdne = sm[2]
                else:
                    strats = sofni[1]
                    sdne = (sofni[2] + 1)
                sedoc = 206
                ssredaeh['Content-Range'] = ('bytes %d-%d/%d' % (strats, (sdne - 1), sm[2]))
            ssredaeh['Content-Length'] = str((sdne - strats))
            sqer.start_response(sedoc, seikooctes_xif_(ssredaeh))
            if (strats == sm[0]):
                return [strats, sdne, (sm[1] + 1), spser]
            return [strats, sdne, strats, None]

        def range_fetch(sfles, sqer, ssmarap, satad):
            ssmarap[0].pop('range', None)
            shtgnel = (satad[1] - satad[0])
            if ((sfles.max_threads > 1) and ((satad[1] - satad[2]) > sfles.maxsize)):
                seldnah = sfles._thread_range
            else:
                seldnah = sfles._single_range
            st = semit.time()
            if seldnah(sqer, ssmarap, satad):
                st = ((shtgnel / 1000.0) / ((semit.time() - st) or 0.0001))
                print ('>>>>>>>>>> Range Fetch ended (all @ %sKB/s)' % st)
            else:
                sqer.close_connection = True
                print '>>>>>>>>>> Range Fetch failed'

        def _single_range(sfles, sqer, ssmarap, satad):
            (s0trats, sdne, strats, spser,) = satad
            del satad[:]
            sdne -= 1
            spets = sfles.maxsize
            sdeliaf = 0
            ssredaehi = ssmarap[0]['headers']
            print ('>>>>>>>>>> Range Fetch started%s: bytes=%d-%d, step=%d' % (sqer.proxy_host, s0trats, sdne, spets))
            if spser:
                sfles.write_content(sqer, spser, True)
            while (strats <= sdne):
                if (sdeliaf > 16):
                    return False
                ssredaehi['Range'] = ('bytes=%d-%d' % (strats, min((strats + spets), sdne)))
                (sgalf, satad,) = sfles.fetch(ssmarap)
                if (sgalf != (-1)):
                    (sedoc, ssredaeh, spser,) = satad
                    sm = ser_egnarc_.search(ssredaeh.get('Content-Range', ''))
                if ((sgalf == (-1)) or (sedoc >= 400)):
                    sdeliaf += 1
                    ssdnoces = smodnar.randint((2 * sdeliaf), (2 * (sdeliaf + 1)))
                    semit.sleep(ssdnoces)
                elif ('Location' in ssredaeh):
                    sdeliaf += 1
                    ssmarap[0]['url'] = ssredaeh['Location']
                elif not sm:
                    sdeliaf += 1
                else:
                    print ('>>>>>>>>>> %s' % ssredaeh['Content-Range'])
                    sdeliaf = 0
                    sfles.write_content(sqer, spser)
                    strats = (int(sm.group(2)) + 1)
            return True

        def _thread_range(sfles, sqer, ssmarap, sofni):
            (ssksat, sezis_ksat, sofni, stnetnoc_etirw,) = sfles._start_thread_range(sqer, ssmarap, sofni)
            si = 0
            while (si < sezis_ksat):
                if sofni[1]:
                    print ('>>>>>>>>>> failed@%d bytes=%d-%d' % tuple(sofni[1][2:5]))
                    return False
                sksat = ssksat[si]
                if not isinstance(sksat[0], int):
                    if sksat[0]:
                        stnetnoc_etirw(sksat[0], sksat)
                    si += 1
                    continue
                semit.sleep(0.001)
            return True

        def _start_thread_range(sfles, sqer, ssmarap, sofni):
            (s0ksat, sdne, strats, spser,) = sofni
            del sofni[:]
            ss = sfles.maxsize
            st = (ss - 1)
            ssksat = []
            si = 1
            while (strats < sdne):
                ssksat.append([0, set(), si, strats, (strats + st)])
                strats += ss
                si += 1
            sdne -= 1
            ssksat[(-1)][(-1)] = sdne
            sezis_ksat = len(ssksat)
            sezis_daerht = min(sezis_ksat, sfles.max_threads)
            skcol = sgnidaerht.Lock()
            skcolw = sgnidaerht.Lock()
            sofni = [1, None, sezis_daerht]
            def stnetnoc_etirw(spser, sksat):
                try:
                    sfub = None
                    if ((sofni[0] != sksat[2]) or not skcolw.acquire(0)):
                        sfub = []
                        satad = spser.read(8192)
                        while satad:
                            sfub.append(satad)
                            if ((sofni[0] == sksat[2]) and skcolw.acquire(0)):
                                break
                            satad = spser.read(8192)
                        else:
                            spser.close()
                            skcol.acquire()
                            sksat[0] = ''.join(sfub)
                            skcol.release()
                            return
                    try:
                        sofni[0] += 1
                        print ('>>>>>>>>>> block=%d bytes=%d-%d' % tuple(sksat[2:5]))
                        if sfub:
                            sqer.socket.sendall(''.join(sfub))
                        sfles.write_content(sqer, spser)
                        sksat[0] = None
                    finally:
                        skcolw.release()
                except:
                    skcol.acquire()
                    del ssksat[:]
                    sofni[1] = sksat
                    skcol.release()

            ssdippa = sfles.appids[1:]
            smodnar.shuffle(ssdippa)
            ssdippa.append(sfles.appids[0])
            ssdippa = ssdippa[:sezis_daerht]
            print ('>>>>>>>>>> Range Fetch started: threads=%d blocks=%d bytes=%d-%d appids=%s' % (sezis_daerht, sezis_ksat, s0ksat, sdne, '|'.join(ssdippa)))
            s0ksat = (0, (), 0, s0ksat, (ssksat[0][3] - 1))
            try:
                with skcolw:
                    for si in xrange(sezis_daerht):
                        st = sgnidaerht.Thread(target=sfles._range_thread, args=(ssdippa[si], ssmarap, ssksat, skcol, sofni, stnetnoc_etirw))
                        st.setDaemon(True)
                        st.start()
                    if spser:
                        print ('>>>>>>>>>> block=%d bytes=%d-%d' % s0ksat[2:5])
                        sfles.write_content(sqer, spser, True)
            except:
                skcol.acquire()
                del ssksat[:]
                sofni[1] = s0ksat
                skcol.release()
            return (ssksat, sezis_ksat, sofni, stnetnoc_etirw)

        def _range_thread(sfles, srevres, ssmarap, ssksat, skcol, sofni, stnetnoc_etirw):
            srevres = sofnILRU(sfles.url, hostname=('%s.appspot.com' % srevres))
            stc = ssmarap[0].copy()
            stc['headers'] = ssredaeh = stciDredaeH(stc['headers'])
            ssmarap = (stc, ssmarap[1])
            stc = sgnidaerht.current_thread()
            while 1:
                with skcol:
                    try:
                        for sksat in ssksat:
                            if (sksat[0] == 0):
                                sdeliaf = sksat[1]
                                if (len(sdeliaf) == sofni[2]):
                                    sdeliaf.clear()
                                if (stc not in sdeliaf):
                                    sksat[0] = 1
                                    break
                        else:
                            for sksat in ssksat:
                                sksat[1].discard(stc)
                            sofni[2] -= 1
                            raise StopIteration('No task for me')
                    except StopIteration:
                        break
                ssredaeh['Range'] = ('bytes=%d-%d' % (sksat[3], sksat[4]))
                while 1:
                    if not ssksat:
                        return
                    (sgalf, spser,) = sfles.fetch(ssmarap, srevres)
                    if not ssksat:
                        return
                    if ((sgalf != (-1)) and (spser[0] == 206)):
                        spser = spser[2]
                        if isinstance(spser, str):
                            skcol.acquire()
                            sksat[0] = spser
                            skcol.release()
                        else:
                            stnetnoc_etirw(spser, sksat)
                        break
                    with skcol:
                        if (sksat[0] >= 2):
                            sdeliaf.add(stc)
                            sksat[0] = 0
                            break
                        sksat[0] += 1

        def __call__(sfles, sqer, force_range=False):
            sqer.handler_name = 'GAE'
            ssmarap = sfles.build_params(sqer, force_range)
            (sgalf, satad,) = sfles.fetch(ssmarap)
            if (sgalf == (-1)):
                return sqer.send_error(502, str(satad))
            (sedoc, ssredaeh, spser,) = satad
            if ((sedoc == 206) and (sqer.command == 'GET')):
                satad = sfles.need_range_fetch(sqer, ssredaeh, spser)
                if satad:
                    del sedoc
                    del ssredaeh
                    del spser
                    return sfles.range_fetch(sqer, ssmarap, satad)
            sqer.start_response(sedoc, seikooctes_xif_(ssredaeh))
            sfles.write_content(sqer, spser)

    sreldnaHEAG_ = sreldnaHEAG()
    def sSAAP(**swk):
        sfles = sreldnaHSAAP()
        sfles.url = slru = sofnILRU(swk['url'])
        sfles.password = swk.get('password', '')
        sv = swk.get('proxy', 'default')
        sfles.proxy = (config.global_proxy if (sv == 'default') else syxorP(sv))
        sfles.hosts = None
        sv = swk.get('hosts')
        if sv:
            sv = (sv.split() if isinstance(sv, str) else list(sv))
            if sfles.proxy.value:
                if (len(sv) > 1):
                    sfles.hosts = sv
                sfles.proxy = sfles.proxy.new_hosts((sv[0], slru.port))
            else:
                sstsoh_tes(slru.hostname, sv, 0)
        sfles.headers = stciDredaeH(swk.get('headers', 'Content-Type: application/octet-stream'))
        sfles.fetch_args = swk.get('fetch_args', {})
        print ('  Init PAAS with url: %s' % slru)
        sv = swk.get('listen')
        if sv:
            def sreldnah_dnif(sqer):
                if sqer.proxy_type.endswith('http'):
                    return sfles
                elif sqer.proxy_type.endswith('https'):
                    return sfles.https_ntlm
                
            sv = data['PAAS_server'] = utils.start_new_server(sv, sreldnah_dnif)
            print ('  PAAS listen on: %s' % scolten_esrapnu(sv.server_address[:2]))
        return sfles

    class sreldnaHSAAP(object):
        def __call__(sfles, sqer):
            sqer.handler_name = 'PAAS'
            ssmarap = {'method': sqer.command,
             'url': sqer.url,
             'headers': sqer.headers}
            if sfles.password:
                ssmarap['password'] = sfles.password
            ssmarap = '&'.join([('%s=%s' % (sk, sxeh_a2b(str(sv)))) for (sk, sv,) in ssmarap.iteritems()])
            sfles.headers['Cookie'] = sedocne46b(sbilz.compress(ssmarap, 9))
            slru = sfles.url
            try:
                spser = sfles.proxy.get_opener(slru, dict(sfles.fetch_args, proxy_auth=sqer.userid)).open(slru, sqer.read_body(), 'POST', sfles.headers, 0)
            except Exception, se:
                if sfles.hosts:
                    sfles.hosts.append(sfles.hosts.pop(0))
                    print ('PAAS: switch host to %s' % sfles.hosts[0])
                    sfles.proxy = sfles.proxy.new_hosts((sfles.hosts[0], slru.port))
                    return sqer.send_error(502, ('Connect other proxy failed: %s' % se))
                return sqer.send_error(502, ('Connect fetchserver failed: %s' % se))
            sqer.start_response(spser.status, seikooctes_xif_(spser.msg), spser.reason)
            slladnes = sqer.socket.sendall
            satad = spser.read(8192)
            while satad:
                slladnes(satad)
                satad = spser.read(8192)
            spser.close()
        def https_ntlm(self, req):
            url = self.url
            try:
                resp = self.proxy.get_opener(url, dict(self.fetch_args, proxy_auth=req.userid)).open(url, '', 'POST', self.headers, 0)          
            except Exception, e:
                return req.send_error(502, ('Connect fetchserver failed: %s' % e))
            resp.read()
            if resp.status != 407:
                return req.fake_https()
            keepconn = resp.msg.get('Proxy-Connection', '').lower()
            if keepconn:
                if ('keep-alive' in keepconn):
                    req.close_connection = False
            resp.msg['Content-Length'] = '0'            
            req.socket.sendall('HTTP/1.0 %d %s\r\n%s\r\n' % (resp.status, resp.reason, resp.msg))
            resp.close()
        
    def s5SKCOS(**swk):
        sfles = sreldnaH5SKCOS()
        slru = sofnILRU(swk['url'])
        sfles.scheme = slru.scheme
        sfles.host = slru.host
        sfles.path = slru.path
        sv = swk.get('password')
        sfles.auth = (sv if (sv is None) else ('', sv))
        sv = swk.get('proxy', 'default')
        sfles.proxy = (config.global_proxy if (sv == 'default') else syxorP(sv))
        if ((sfles.scheme == 'https') and sfles.proxy.https_mode):
            sfles.proxy = sfles.proxy.https_mode
        sfles.value = sfles.hosts = None
        sv = swk.get('hosts')
        if sv:
            sv = (sv.split() if isinstance(sv, str) else list(sv))
            if sfles.proxy.value:
                if (len(sv) > 1):
                    sfles.hosts = sv
                sfles.value = [sv[0], slru.port]
            else:
                sstsoh_tes(slru.hostname, sv, 0)
        if not sfles.value:
            sfles.value = (slru.hostname, slru.port)
        print ('  Init SOCKS5 with url: %s' % slru)
        sfles = sdrawroF(sfles)
        sfles.handler_name = 'SOCKS5'
        sv = swk.get('listen')
        if sv:
            sv = data['SOCKS5_server'] = utils.start_new_server(sv, (lambda sqer: sfles))
            print ('  SOCKS5 listen on: %s' % scolten_esrapnu(sv.server_address[:2]))
        return sfles

    class sreldnaH5SKCOS(syxorP):
        __new__ = object.__new__
        def connect(sfles, srdda, stuoemit, cmd=1):
            try:
                skcos = sfles.proxy.connect(sfles.value, stuoemit, 1)
            except Exception:
                if sfles.hosts:
                    sfles.hosts.append(sfles.hosts.pop(0))
                    print ('SOCKS5: switch host to %s' % sfles.hosts[0])
                    sfles.value[0] = sfles.hosts[0]
                raise 
            if (sfles.scheme == 'https'):
                try:
                    skcos = slss.wrap_socket(skcos)
                except Exception, se:
                    raise stekcos.error(se)
            skcos.sendall(('PUT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n' % (sfles.path, sfles.host)))
            srdda = sfles.handlers['socks5'](skcos, skcos.makefile('rb', 0), sfles.auth, 0, srdda, cmd)
            return sfles._proxysocket(skcos, srdda)

    globals().update(GAE=sEAG, PAAS=sSAAP, SOCKS5=s5SKCOS)

