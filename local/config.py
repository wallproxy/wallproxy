# -*- coding: utf-8 -*-
# 是否使用ini作为配置文件，0不使用
ini_config = 1391657668
# 监听ip
listen_ip = '127.0.0.1'
# 监听端口
listen_port = 8086
# 是否使用通配符证书
cert_wildcard = 1
# 更新PAC时也许还没联网，等待tasks_delay秒后才开始更新
tasks_delay = 0
# WEB界面是否对本机也要求认证
web_authlocal = 0
# 登录WEB界面的用户名
web_username = 'admin'
# 登录WEB界面的密码
web_password = 'admin'
# 全局代理
global_proxy = None
# URLFetch参数
fetch_keepalive = 1
check_update = 0

def config():
    Forward, set_dns, set_resolve, set_hosts, check_auth, redirect_https = import_from('util')
    RAW_FORWARD = FORWARD = Forward()
    set_dns('168.95.1.1')
    set_resolve('talk.google.com talkx.l.google.com .youtube.com .facebook.com .googlevideo.com')
    google_sites = ('.appspot.com', '.google.com', '.google.com.hk', '.googlecode.com', '.googleusercontent.com', '.googlegroups.com', '.google-analytics.com', '.gstatic.com', '.googleapis.com', '.blogger.com', '.ggpht.com', 'golang.org')
    google_hosts = 'www.google.com www.google.com.hk mail.google.com www.google.at www.google.es www.google.ca www.google.com.mx www.google.com.pa www.google.gl www.google.com.gt www.google.com.bz www.google.com.sv www.google.hn'
    set_hosts(google_sites, google_hosts)
    set_hosts('www.youtube.com upload.youtube.com', google_hosts)

    from plugins import misc; misc = install('misc', misc)
    PAGE = misc.Page('page.html')

    from plugins import paas; paas = install('paas', paas)
    GAE = paas.GAE(appids=['akb48daisukilove', 'freegoagent993', 'goagent-dup002', 'freegoagent863', 'freegoagent623', 'goagent-dup001', 'freegoagent832', 'freegoagent831', 'freegoagent625', 'freegoagent945', 'freegoagent872', 'freegoagent830', 'freegoagent866', 'freegoagent685', 'freegoagent965', 'smartladdercanada', 'freegoagent825', 'freegoagent898', 'freegoagent205', 'freegoagent701', 'aitaiyokani', 'freegoagent987', 'freegoagent766', 'smartladder8', 'freegoagent703', 'freegoagent358', 'freegoagent654', 'smartladder2', 'freegoagent847', 'freegoagent840', 'freegoagent586', 'freegoagent968', 'sandaojushi3', 'freegoagent978', 'smartladderuk', 'freegoagent875', 'freegoagent638', 'f360uck', 'kawaiiushio7', 'freegoagent998', 'freegoagent861', 'freegoagent789', 'freegoagent576', 'freegoagent889', 'freegoagent905', 'freegoagent975', 'freegoagent710', 'freegoagent553', 'freegoagent655', 'freegoagent292', 'freegoagent828', 'freegoagent874', 'fangbingxingtodie', 'freegoagent881', 'kawaiiushioplus', 'freegoagent994', 'freegoagent799', 'gonggongid10', 'freegoagent926', 'freegoagent818', 'freegoagent758', 'window8saiko', 'smartladderhongkong', 'freegoagent949', 'ftencentuck', 'kawaiiushio', 'freegoagent909', 'freegoagent578', 'freegoagent793', 'chrometieba', 'freegoagent734', 'freegoagent657', 'freegoagent809', 'freegoagent879', 'smartladderus', 'freegoagent915', 'freegoagent698', 'freegoagent822', 'smartladderjapan', 'freegoagent927', 'freegoagent674', 'freegoagent771', 'freegoagent802', 'kawaiiushio8', 'freegoagent963', 'gongmin700', 'freegoagent791', 'freegoagent974', 'freegoagent923', 'freegoagent744', 'freegoagent877', 'freegoagent746', 'goagent-dup003', 'freegoagent774', 'freegoagent670', 'freegoagent976', 'freegoagent633', 'freegoagent876', 'smartladder6', 'kawaiiushio4', 'freegoagent699', 'freegoagent956', 'gonggongid06', 'freegoagent785', 'chrome360q', 'gonggongid01', 'kawaiiushio6', 'freegoagent737', 'smartladder3', 'smartladder1', 'gonggongid09', 'freegoagent971', 'freegoagent666', 'freegoagent671', 'freegoagent591', 'freegoagent644', 'freegoagent526', 'sekaiwakerei', 'freegoagent773', 'freegoagent702', 'freegoagent760', 'ippotsukobeta', 'freegoagent547', 'freegoagent811', 'kawaiiushio5', 'gonggongid04', 'freegoagent813', 'freegoagent628', 'gonggongid07', 'freegoagent966', 'freegoagent837', 'yanlun001', 'feijida600', 'chromeichi', 'freegoagent577', 'freegoagent957', 'freegoagent707', 'freegoagent494', 'gongongid02', 'freegoagent777', 'freegoagent786', 'freegoagent812', 'freegoagent334', 'yugongxisaiko', 'chromeqq', 'freegoagent951', 'diaoyudaobelongtochinasaiko', 'chromelucky', 'freegoagent781', 'freegoagent784', 'ilovesmartladder', 'freegoagent900', 'freegoagent616', 'smartladder4', 'freegoagent894', 'freegoagent932', 'freegoagent603', 'freegoagent631', 'freegoagent934', 'freegoagent928', 'gonggongid05', 'freegoagent807', 'freegoagent972', 'freegoagent794', 'baidufirefoxtieba', 'freegoagent160', 'freegoagent852', 'freegoagent958', 'bakabaka300', 'smartladdertaiwan', 'saosaiko', 'qq325862401', 'freegoagent583', 'gfwdies', 'freegoagent686', 'chromesaiko', 'freegoagent762', 'freegoagent867', 'freegoagent742', 'freegoagent859', 'freegoagent973', 'freegoagent753', 'freegoagent624', 'freegoagent954', 'freegoagent981', 'kawaiiushio9', 'freegoagent730', 'freegoagent929', 'freegoagent810', 'freegoagent914', 'freegoagent855', 'smartladder7', 'freegoagent870', 'baiduchrometieba', 'kawaiiushio2', 'freegoagent641', 'freegoagent836', 'jianiwoxiangni', 'freegoagent607', 'freegoagent851', 'freegoagent650', 'freegoagent585', 'freegoagent198', 'freegoagent599', 'bakajing600', 'freegoagent718', 'freegoagent910', 'freegoagent950', 'gonggongid08', 'freegoagent827', 'flowerwakawaii', 'smartladderchina', 'smartladderkoera', 'gonggongid03', 'freegoagent780', 'freegoagent919', 'kawaiiushionoserve', 'kawaiiushio1'], listen='8087', path='/fetch.py', scheme='https', hosts=google_hosts, max_threads=3, fetch_mode=1)

    PacFile, RuleList, HostList = import_from('pac')
    def apnic_parser(data):
        from re import findall
        return '\n'.join(findall(r'(?i)\|cn\|ipv4\|((?:\d+\.){3}\d+\|\d+)\|', data))
    forcehttps_sites = RuleList('http://*.appspot.com/ \n http://*.google.com/ \n http://*.google.com.hk/ \n http://*.googlecode.com/ \n http://*.googleusercontent.com/ \n http://*.blogger.com/ \n http://www.youtube.com/ \n @@http://books.google.com/ \n @@http://translate.google.com/ \n @@http://scholar.google.com/ \n @@http://feedproxy.google.com/ \n @@http://fusion.google.com/ \n @@http://picasa.google.com/ \n @@http://*pack.google.com/ \n @@http://*android.clients.google.com/ \n @@http://wenda.google.com.hk/ \n @@http://www.google.com*/imgres? \n @@http://www.google.com*/translate_t? \n @@http://www.google.com/analytics/ \n @@http://wiki.*.googlecode.com/ \n @@http:/// \n @@http://website.*.googlecode.com/ \n @@http://www.google.com*/custom? \n @@http://www.google.com/dl/ \n @@http://www.google.com/drive/ \n @@http://www.google.com*/alerts?')
    autorange_rules = RuleList('||c.youtube.com \n ||atm.youku.com \n ||googlevideo.com \n http*://av.vimeo.com/ \n http*://smile-*.nicovideo.jp/ \n http*://video.*.fbcdn.net/ \n http*://s*.last.fm/ \n http*://x*.last.fm/ \n ||x.xvideos.com \n ||edgecastcdn.net \n ||d.rncdn3.com \n http*://cdn*.public.tube8.com/ \n http*://videos.flv*.redtubefiles.com/ \n http*://cdn*.public.extremetube.phncdn.com/ \n http*://cdn*.video.pornhub.phncdn.com/ \n ||mms.vlog.xuite.net \n http*://vs*.thisav.com/ \n http*://archive.rthk.hk/ \n http*://video*.modimovie.com/ \n http*://v*.cache*.c.docs.google.com/ \n /^https?:\\/\\/[^\\/]+\\/[^?]+\\.(?:cab|f4v|flv|hlv|m4v|mp4|mp3|ogg|avi|exe|zip|iso|ipa|rar|bz2|xz|deb|dmg|3gp)(?:$|\\?)/ \n http*://*.googleusercontent.com/videoplayback?')
    _GAE = GAE; GAE = lambda req: _GAE(req, autorange_rules.match(req.url, req.proxy_host[0]))
    import re; useragent_match = re.compile('(?i)mobile').search
    useragent_rules = RuleList('||twitter.com')
    withgae_sites = RuleList('||c.docs.google.com \n ||translate.google.com \n http*://books.google.com/books?id= \n http*://*.googleusercontent.com/videoplayback?')
    notruehttps_sites = HostList('.docs.google.com translate.google.com books.google.com')
    truehttps_sites = HostList('.appspot.com .google.com .google.com.hk .googlecode.com .googleusercontent.com .googlegroups.com .google-analytics.com .gstatic.com .googleapis.com .blogger.com .ggpht.com')
    crlf_rules = RuleList('/^https?:\\/\\/[^\\/]+\\.c\\.youtube\\.com\\/liveplay\\?/ \n /^https?:\\/\\/upload\\.youtube\\.com\\// \n /^https?:\\/\\/www\\.youtube\\.com\\/upload\\// \n /^https?:\\/\\/[^\\/]+\\.googlevideo\\.com\\/crossdomain\\.xml/')
    hosts_rules = RuleList(' \n ||appspot.com \n ||google.com \n ||google.com.hk \n ||googlecode.com \n ||googleusercontent.com \n ||googlegroups.com \n ||google-analytics.com \n ||gstatic.com \n ||googleapis.com \n ||blogger.com \n ||ggpht.com \n ||golang.org')
    unparse_netloc = import_from('utils')
    def build_fake_url(scheme, host):
        if scheme == 'https' and host[1] != 80 or host[1] % 1000 == 443:
            scheme, dport = 'https', 443
        else: scheme, dport = 'http', 80
        return '%s://%s/' % (scheme, unparse_netloc(host, dport))
    _HttpsFallback = (GAE,)
    nofallback_rules = RuleList('/^https?:\\/\\/(?:[\\w-]+|127(?:\\.\\d+){3}|10(?:\\.\\d+){3}|192\\.168(?:\\.\\d+){2}|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d+){2}|\\[.+?\\])(?::\\d+)?\\//')
    def FORWARD(req):
        if req.proxy_type.endswith('http'):
            if nofallback_rules.match(req.url, req.proxy_host[0]):
                return RAW_FORWARD(req)
            return RAW_FORWARD(req, GAE)
        url = build_fake_url(req.proxy_type, req.proxy_host)
        if nofallback_rules.match(url, req.proxy_host[0]):
            return RAW_FORWARD(req)
        return RAW_FORWARD(req, _HttpsFallback)

    rulelist = (
        (RuleList(['https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', 'userlist.ini']), GAE),
    )
    httpslist = (
        (rulelist[0][0], None),
    )

    def find_gae_handler(req):
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if proxy_type.endswith('http'):
            url = req.url
            if useragent_match(req.headers.get('User-Agent','')) and useragent_rules.match(url, host):
                req.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4'
            if withgae_sites.match(url, host):
                return GAE
            needhttps = req.scheme == 'http' and forcehttps_sites.match(url, host) and req.content_length == 0
            if needhttps and getattr(req, '_r', '') != url:
                req._r = url
                return redirect_https
            if crlf_rules.match(url, host):
                req.crlf = 1
                return FORWARD
            if not needhttps and hosts_rules.match(url, host):
                return FORWARD
            return GAE
        if notruehttps_sites.match(host): return
        if truehttps_sites.match(host): return FORWARD
    paas.data['GAE_server'].find_handler = find_gae_handler

    def find_proxy_handler(req):
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if proxy_type.endswith('http'):
            url = req.url
            if useragent_match(req.headers.get('User-Agent','')) and useragent_rules.match(url, host):
                req.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4'
            if withgae_sites.match(url, host):
                return GAE
            needhttps = req.scheme == 'http' and forcehttps_sites.match(url, host) and req.content_length == 0
            if needhttps and getattr(req, '_r', '') != url:
                req._r = url
                return redirect_https
            if crlf_rules.match(url, host):
                req.crlf = 1
                return FORWARD
            if not needhttps and hosts_rules.match(url, host):
                return FORWARD
            for rule,target in rulelist:
                if rule.match(url, host):
                    return target
            return FORWARD
        if notruehttps_sites.match(host): return
        if truehttps_sites.match(host): return FORWARD
        url = build_fake_url(proxy_type, (host, port))
        for rule,target in httpslist:
            if rule.match(url, host):
                return target
        return FORWARD
    return find_proxy_handler
