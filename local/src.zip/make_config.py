# -*- coding: utf-8 -*-
from __future__ import with_statement

PUBLIC_APPIDS = '''
smartladder8|sandaojushi3|ftencentuck|baidufirefoxtieba|chromeichi|aitaiyokani|smartladder3|mzmzmz001|smartladder4|chrome360q|smartladder6|goagent-dup001|kawaiiushioplus|smartladdercanada|gongongid02|goagent-dup003|goagent-dup002|gonggongid03|ippotsukobeta|gonggongid01|gonggongid07|gonggongid06|kawaiiushionoserve|gonggongid04|kawaiiushio2|chromelucky|gonggongid09|yanlun001|smartladderchina|smartladder1|kawaiiushio1|kawaiiushio6|kawaiiushio7|saosaiko|kawaiiushio5|smartladderjapan|bakajing600|sekaiwakerei|yugongxisaiko|gonggongid08|smartladder2|baiduchrometieba|kawaiiushio4|gonggongid05|bakabaka300|fangbingxingtodie|f360uck|chromesaiko|chromeqq|kawaiiushio|ilovesmartladder|smartladder7|gongmin700|qq325862401|kawaiiushio8|smartladderkoera|gonggongid10|kawaiiushio9|smartladderuk|smartladderhongkong|chrometieba|flowerwakawaii|feijida600|window8saiko|gfwdies|smartladdertaiwan|akb48daisukilove|smartladderus|diaoyudaobelongtochinasaiko|jianiwoxiangni
'''

import ConfigParser, os, re, urlparse, os.path as ospath, random
from cStringIO import StringIO

rulefiles = lambda v:[v.replace(r'\n','\n') if v.startswith('string://') else v for v in v.split('|')]

class Common(object):
    v = '''def %s(self, *a):
    try:
        return self.CONFIG.%s(*a[:-1])
    except:
        return a[-1]
'''
    for k in ('get', 'getint', 'getfloat', 'getboolean', 'items', 'remove_option'):
        exec(v % (k, k))
    del k, v

    def parse_pac_config(self):
        v = self.get('pac', 'py_default', '') or 'FORWARD'
        self.PY_DEFAULT = (v.split('|') * 3)[:3]
        if self.PAC_FILE:
            v = self.get('pac', 'default', '') or self._PAC_DEFAULT
            self.PAC_DEFAULT = (v.split('|') * 3)[:3]
        else:
            self.PAC_DEFAULT = self.PY_DEFAULT
        def get_rule_cfg(key, default):
            PAC_RULELIST = v = self.get('pac', key, default)
            if v.startswith('!'):
                if self.PAC_FILE:
                    v = self.items(v.lstrip('!').strip(), ())
                    v = [(rulefiles(v),k.upper()) for k,v in v if k and v]
                else:
                    v = self.items('py_'+v.lstrip('!').strip(), ())
                    sp = {'FORBID':'False', 'WEB':'None'}
                    v = [(rulefiles(v),sp.get(k.upper()) or k.upper()) for k,v in v if k and v]
                PAC_RULELIST = v
            elif v:
                TARGET_PAC = self.TARGET_PAAS
                if self.PAC_FILE:
                    TARGET_PAC = self.TARGET_LISTEN
                    if not TARGET_PAC:
                        TARGET_PAC = '*:*'
                    elif ':' not in TARGET_PAC:
                        TARGET_PAC = '*:' + TARGET_PAC
                    TARGET_PAC = 'PROXY %s;DIRECT' % TARGET_PAC
                PAC_RULELIST = [(rulefiles(v), TARGET_PAC)]
            return PAC_RULELIST
        self.PAC_RULELIST = get_rule_cfg('rulelist', '')
        self.PAC_IPLIST = get_rule_cfg('iplist', '')

    def __init__(self, INPUT):
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        CONFIG = self.CONFIG = ConfigParser.ConfigParser()
        try:
            CONFIG.read(INPUT)
        except ConfigParser.MissingSectionHeaderError:
            with open(INPUT, 'rb') as fp: v = fp.read()
            v = v[v.find('['):]
            try:
                with open(INPUT, 'wb') as fp: fp.write(v)
            except IOError:
                pass
            CONFIG.readfp(StringIO(v), INPUT)

        self.LISTEN_IP          = self.get('listen', 'ip', '0.0.0.0')
        self.LISTEN_PORT        = self.getint('listen', 'port', 8086)
        self.USERNAME           = self.get('listen', 'username', None)
        self.WEB_USERNAME       = self.get('listen', 'web_username', 'admin')
        self.WEB_PASSWORD       = self.get('listen', 'web_password', 'admin')
        self.WEB_AUTHLOCAL      = self.getboolean('listen', 'web_authlocal', False)
        if self.USERNAME is not None:
            self.PASSWORD       = self.get('listen', 'password', '')
            self.BASIC_AUTH     = self.getboolean('listen', 'basic_auth', True)
            self.DISABLE_SOCKS4 = self.getboolean('listen', 'disable_socks4', False)
            self.DISABLE_SOCKS5 = self.getboolean('listen', 'disable_socks5', False)
        self.CERT_WILDCARD      = self.getboolean('listen', 'cert_wildcard', True)
        self.TASKS_DELAY        = self.getint('listen', 'tasks_delay', 0)

        self.FETCH_KEEPALIVE    = self.getboolean('urlfetch', 'keep_alive', True)
        self.FETCH_TIMEOUT      = self.getfloat('urlfetch', 'timeout', -1)
        self.FORWARD_TIMEOUT    = self.getfloat('urlfetch', 'fwd_timeout', -1)
        self.FETCH_ARGS = v = {}
        k = self.getfloat('urlfetch', 'gae_timeout', -1)
        if k >= 0: v['timeout'] = k or None
        k = self.getint('urlfetch', 'gae_crlf', 0)
        if k > 0: v['crlf'] = k
        self.DEBUG_LEVEL        = self.getint('urlfetch', 'debug', -1)

        GAE_PROFILE = 'gae'; self.GAE_HANDLER = False
        self.GAE_ENABLE         = self.getboolean('gae', 'enable', CONFIG.has_section('gae'))
        if self.GAE_ENABLE:
            self.GAE_LISTEN     = self.get('gae', 'listen', '8087')
            if self.LISTEN_PORT == 8087 and self.GAE_LISTEN == '8087':
                self.LISTEN_PORT = 8086
            v = self.get('gae', 'appid', '').replace('.appspot.com', '')
            if not v or v == 'appid1|appid2':
                self.GAE_APPIDS = v = re.sub(r'\s+', '', PUBLIC_APPIDS).split('|')
                random.shuffle(v)
            else:
                self.GAE_APPIDS = v.split('|')
            self.GAE_PASSWORD   = self.get('gae', 'password', '')
            self.GAE_PATH       = self.get('gae', 'path', '/fetch.py')
            GAE_PROFILE         = self.get('gae', 'profile', GAE_PROFILE)
            self.GAE_MAXTHREADS = self.getint('gae', 'max_threads', 0)
            v = self.getint('gae', 'fetch_mode', 0)
            self.GAE_FETCHMOD   = 0 if v <= 0 else (2 if v >= 2 else 1)
            self.GAE_PROXY      = self.get('gae', 'proxy', 'default')
            self.GAE_HANDLER    = self.GAE_LISTEN and self.getboolean('gae', 'find_handler', True)

        self.PAAS_ENABLE        = self.getboolean('paas', 'enable', CONFIG.has_section('paas'))
        if self.PAAS_ENABLE:
            self.PAAS_LISTEN        = self.get('paas', 'listen', '')
            self.PAAS_PASSWORD      = self.get('paas', 'password', '')
            self.PAAS_FETCHSERVER   = CONFIG.get('paas', 'fetchserver').split('|')
            self.PAAS_PROXY         = self.get('paas', 'proxy', 'default')

        self.SOCKS5_ENABLE      = self.getboolean('socks5', 'enable', CONFIG.has_section('socks5'))
        if self.SOCKS5_ENABLE:
            self.SOCKS5_LISTEN      = self.get('socks5', 'listen', '')
            self.SOCKS5_PASSWORD    = self.get('socks5', 'password', '')
            self.SOCKS5_FETCHSERVER = CONFIG.get('socks5', 'fetchserver')
            self.SOCKS5_PROXY       = self.get('socks5', 'proxy', 'default')

        OLD_PLUGIN = []
        d = {'gaeproxy':'OGAE', 'forold':'OOLD', 'goagent':'OGA', 'simple':'OSP', 'simple2':'OSP2'}
        for k in d:
            if self.getboolean(k, 'enable', CONFIG.has_section(k)):
                url = self.get(k, 'url', '')
                if url: url = url.split('|')
                else:
                    url = self.get(k, 'appid', '')
                    if not url: continue
                    url = ['https://%s.appspot.com/%s.py' % (i,k) for i in url.split('|')]
                crypto = (self.get(k, 'crypto', '') + '|'*20).split('|')
                key = self.get(k, 'password', '').decode('string-escape')
                key = (key + ('|'+key)*20).split('|')
                proxy = [v.split(',') if ',' in v else v for v in (self.get(k, 'proxy', 'default')+'|'*20).split('|')]
                configs = []
                for url,crypto,key,proxy in zip(url,crypto,key,proxy):
                    config = {'url':url, 'key':key}
                    if crypto: config['crypto'] = crypto
                    if proxy == 'none':
                        config['proxy'] = None
                    elif proxy:
                        config['proxy'] = proxy
                    configs.append(config)
                for v in ('max_threads', 'range0', 'range'):
                    configs[0][v] = self.getint(k, v, 0)
                OLD_PLUGIN.append((d[k], k, configs, self.get(k, 'listen', '')))
        self.OLD_PLUGIN = OLD_PLUGIN or False

        self.TARGET_PAAS        = self.GAE_ENABLE and 'GAE' or self.PAAS_ENABLE and 'PAAS' or self.SOCKS5_ENABLE and 'SOCKS5' or self.OLD_PLUGIN and self.OLD_PLUGIN[0][0]
        self.TARGET_LISTEN = self.GAE_ENABLE and self.GAE_LISTEN or self.PAAS_ENABLE and self.PAAS_LISTEN or self.SOCKS5_ENABLE and self.SOCKS5_LISTEN or self.OLD_PLUGIN and self.OLD_PLUGIN[0][3]

        v = self.getint('proxy', 'enable', 0)
        self._PAC_DEFAULT = 'DIRECT'; self.GLOBAL_PROXY = None
        if v > 0:
            PROXIES = []
            for i in xrange(1,v+1):
                v = self.get('proxy', 'proxy%d'%i, '')
                if not v: break
                PROXIES.append(v)
            if not PROXIES:
                PROXY_HOST      = CONFIG.get('proxy', 'host')
                PROXY_PORT      = CONFIG.getint('proxy', 'port')
                PROXY_USERNAME  = self.get('proxy', 'username', '')
                PROXY_PASSWROD  = self.get('proxy', 'password', '')
                self._PAC_DEFAULT= 'PROXY %s:%s;DIRECT' % (PROXY_HOST, PROXY_PORT)
                if PROXY_USERNAME:
                    PROXY_HOST = '%s:%s@%s' % (PROXY_USERNAME, PROXY_PASSWROD, PROXY_HOST)
                PROXIES.append('http://%s:%s' % (PROXY_HOST, PROXY_PORT))
            self.GLOBAL_PROXY   = PROXIES[0] if len(PROXIES) == 1 else tuple(PROXIES)

        self.HTTPS_TARGET = {}
        if self.getboolean('forward', 'enable', CONFIG.has_section('forward')):
            self.remove_option('forward', 'enable', '')
            for k,v in self.items('forward', ()):
                self.HTTPS_TARGET[k.upper()] = '(%s)'%v if '"' in v or "'" in v else repr(v)

        self.PAC_ENABLE = self.getboolean('pac', 'enable', True)
        v = self.getint('pac', 'https_mode', 2)
        self.PAC_HTTPSMODE = 0 if v <= 0 else (2 if v >= 2 else 1)
        v = self.get('pac', 'file', '').replace('goagent', 'proxy')
        self.PAC_FILE = v and v.split('|')
        self.parse_pac_config()

        self.GOOGLE_MODE        = self.get(GAE_PROFILE, 'mode', 'http')
        v = self.get(GAE_PROFILE, 'hosts', '')
        self.GOOGLE_HOSTS       = ' '.join(v and tuple(v.split('|')) or ())
        v = self.get(GAE_PROFILE, 'sites', '')
        self.GOOGLE_SITES       = v and tuple(v.split('|')) or ()
        v = self.get(GAE_PROFILE, 'forcehttps', ''); v = v and v.split('|') or ()
        GOOGLE_FORCEHTTPS = [(i if '/' in i else ('http://%s/'%('*'+i if i.startswith('.') else i))) for i in v]
        v = self.get(GAE_PROFILE, 'noforcehttps', ''); v = v and v.split('|') or ()
        GOOGLE_FORCEHTTPS.extend(['@@%s'%(i if '/' in i else ('http://%s/'%('*'+i if i.startswith('.') else i))) for i in v])
        self.GOOGLE_FORCEHTTPS = ' \n '.join(GOOGLE_FORCEHTTPS)
        v = self.get(GAE_PROFILE, 'withgae', '')
        GOOGLE_WITHGAE          = v and tuple(v.split('|')) or ()
        self.TRUE_HTTPS = self.TARGET_PAAS and self.get(GAE_PROFILE, 'truehttps', '').replace('|', ' ').strip()
        self.NOTRUE_HTTPS = self.TRUE_HTTPS and self.get(GAE_PROFILE, 'notruehttps', '').replace('|', ' ').strip()

        self.FETCHMAX_LOCAL     = self.getint('fetchmax', 'local', 3)
        self.FETCHMAX_SERVER    = self.getint('fetchmax', 'server', 0)

        self.AUTORANGE_ENABLE   = self.getboolean('autorange', 'enable', False)
        def get_rules(opt, key, d=''):
            v = self.get(opt, key, d)
            if v.startswith('!'):
                v = v.lstrip('!').strip()
                return v and rulefiles(v)
            else:
                return v.replace(r'\n', '\n').strip()
        self.AUTORANGE_RULES = get_rules('autorange', 'rules')
        v = self.get('autorange', 'hosts', ''); v = v and v.split('|') or ()
        v = ' \n '.join([(i if '/' in i else ('||%s'%i.lstrip('.') if i.startswith('.') else 'http*://%s/'%i)) for i in v])
        if isinstance(self.AUTORANGE_RULES, list):
            self.AUTORANGE_RULES.append('string://' + v)
        elif v:
            self.AUTORANGE_RULES = ' \n '.join((v, self.AUTORANGE_RULES))
        self.AUTORANGE_MAXSIZE  = self.getint('autorange', 'maxsize', 1000000)
        self.AUTORANGE_WAITSIZE = self.getint('autorange', 'waitsize', 500000)
        self.AUTORANGE_BUFSIZE  = self.getint('autorange', 'bufsize', 8192)

        assert self.AUTORANGE_BUFSIZE <= self.AUTORANGE_WAITSIZE <= self.AUTORANGE_MAXSIZE

        self.REMOTE_DNS = self.DNS_RESOLVE = self.CRLF_RULES = self.HOSTS_RULES = ''; self.HOSTS = {}
        if self.getboolean('hosts', 'enable', CONFIG.has_section('hosts')):
            self.REMOTE_DNS = v = self.get('hosts', 'dns', '')
            if v: self.REMOTE_DNS = v if ',' in v else repr(v)
            self.DNS_RESOLVE = self.get('hosts', 'resolve', '').replace('|', ' ').strip()
            self.HOSTS_CRLF = self.getint('hosts', 'crlf', 0)
            self.CRLF_RULES = self.HOSTS_CRLF > 0 and get_rules('hosts', 'crlf_rules')
            self.HOSTS_RULES = self.TARGET_PAAS and get_rules('hosts', 'rules')
            for v in ('enable', 'rules', 'crlf', 'crlf_rules', 'dns', 'resolve'):
                self.remove_option('hosts', v, '')
            for k,v in self.items('hosts', ()):
                if v.startswith('profile:'):
                    v = self.get(GAE_PROFILE, v[8:], '')
                else:
                    m = re.match(r'\[(\w+)\](\w+)', v)
                    if m:
                        v = v.replace(m.group(0), self.get(m.group(1), m.group(2), ''))
                v = v.replace('|', ' ').strip()
                if k and v: self.HOSTS[k] = v

        self.THIRD_APPS = []
        if self.getboolean('third', 'enable', CONFIG.has_section('third')):
            self.remove_option('third', 'enable', '')
            self.THIRD_APPS = [(k,v if v[0] in ('"',"'") else repr(v)) for k,v in self.items('third', ()) if v]

        self.USERAGENT_STRING   = self.getboolean('useragent', 'enable', True) and self.get('useragent', 'string', '')
        self.USERAGENT_MATCH    = self.USERAGENT_STRING and self.get('useragent', 'match', '')
        self.USERAGENT_RULES    = self.USERAGENT_MATCH and get_rules('useragent', 'rules')
        self.FALLBACK_RULES     = self.TARGET_PAAS and get_rules('urlfetch', 'nofallback',
            r'/^https?:\/\/(?:[\w-]+|127(?:\.\d+){3}|10(?:\.\d+){3}|192\.168(?:\.\d+){2}|172\.[1-3]\d(?:\.\d+){2}|\[.+?\])(?::\d+)?\//')

        self.AUTORANGE_RULES    = (self.GAE_ENABLE or self.OLD_PLUGIN) and self.AUTORANGE_ENABLE and self.AUTORANGE_RULES
        self.PAC_ENABLE         = (self.PAC_RULELIST or self.PAC_IPLIST) and self.PAC_ENABLE and 'PAC_ENABLE'
        self.GOOGLE_WITHGAE     = False
        if self.TARGET_PAAS and self.GOOGLE_SITES and not self.GLOBAL_PROXY:
            self.GOOGLE_WITHGAE = ' \n '.join([(i if '/' in i else '||%s'%i.lstrip('.')) for i in GOOGLE_WITHGAE])
            v = ' \n '.join(['||%s'%i.lstrip('.') for i in self.GOOGLE_SITES])
            if isinstance(self.HOSTS_RULES, basestring):
                self.HOSTS_RULES = ' \n '.join((self.HOSTS_RULES, v))
            else:
                self.HOSTS_RULES.append('string://' + v)
        self.NEED_PAC           = self.GOOGLE_FORCEHTTPS or self.USERAGENT_RULES or self.FALLBACK_RULES or self.AUTORANGE_RULES or self.CRLF_RULES or self.HOSTS_RULES or self.GOOGLE_WITHGAE or self.PAC_ENABLE


def tob(s, enc='utf-8'):
    return s.encode(enc) if isinstance(s, unicode) else bytes(s)
def touni(s, enc='utf-8', err='strict'):
    return s.decode(enc, err) if isinstance(s, str) else unicode(s)

class SimpleTemplate(object):
    """SimpleTemplate from bottle"""
    blocks = ('if', 'elif', 'else', 'try', 'except', 'finally', 'for', 'while',
              'with', 'def', 'class')
    dedent_blocks = ('elif', 'else', 'except', 'finally')
    re_pytokens = re.compile(r'''
            (''(?!')|""(?!")|'{6}|"{6}    # Empty strings (all 4 types)
             |'(?:[^\\']|\\.)+?'          # Single quotes (')
             |"(?:[^\\"]|\\.)+?"          # Double quotes (")
             |'{3}(?:[^\\]|\\.|\n)+?'{3}  # Triple-quoted strings (')
             |"{3}(?:[^\\]|\\.|\n)+?"{3}  # Triple-quoted strings (")
             |\#.*                        # Comments
            )''', re.VERBOSE)

    def __init__(self, source, encoding='utf-8'):
        self.source = source
        self.encoding = encoding
        self._str = lambda x: touni(repr(x), encoding)
        self._escape = lambda x: touni(x, encoding)

    @classmethod
    def split_comment(cls, code):
        """ Removes comments (#...) from python code. """
        if '#' not in code: return code
        #: Remove comments only (leave quoted strings as they are)
        subf = lambda m: '' if m.group(0)[0]=='#' else m.group(0)
        return re.sub(cls.re_pytokens, subf, code)

    @property
    def co(self):
        # print self.code
        return compile(self.code, '<string>', 'exec')

    @property
    def code(self):
        stack = [] # Current Code indentation
        lineno = 0 # Current line of code
        ptrbuffer = [] # Buffer for printable strings and token tuple instances
        codebuffer = [] # Buffer for generated python code
        multiline = dedent = oneline = False
        template = self.source

        def yield_tokens(line):
            for i, part in enumerate(re.split(r'\{\{(.*?)\}\}', line)):
                if i % 2:
                    if part.startswith('!'): yield 'RAW', part[1:]
                    else: yield 'CMD', part
                else: yield 'TXT', part

        def flush(): # Flush the ptrbuffer
            if not ptrbuffer: return
            cline = ''
            for line in ptrbuffer:
                for token, value in line:
                    if token == 'TXT': cline += repr(value)
                    elif token == 'RAW': cline += '_str(%s)' % value
                    elif token == 'CMD': cline += '_escape(%s)' % value
                    cline +=  ', '
                cline = cline[:-2] + '\\\n'
            cline = cline[:-2]
            if cline[:-1].endswith('\\\\\\\\\\n'):
                cline = cline[:-7] + cline[-1] # 'nobr\\\\\n' --> 'nobr'
            cline = '_printlist([' + cline + '])'
            del ptrbuffer[:] # Do this before calling code() again
            code(cline)

        def code(stmt):
            for line in stmt.splitlines():
                codebuffer.append('  ' * len(stack) + line.strip())

        for line in template.splitlines(True):
            lineno += 1
            line = touni(line, self.encoding)
            sline = line.lstrip()
            if lineno <= 2:
                m = re.match(r"%\s*#.*coding[:=]\s*([-\w.]+)", sline)
                if m: self.encoding = m.group(1)
                if m: line = line.replace('coding','coding (removed)')
            if sline and sline[0] == '%' and sline[:2] != '%%':
                line = line.split('%',1)[1].lstrip() # Full line following the %
                cline = self.split_comment(line).strip()
                cmd = re.split(r'[^a-zA-Z0-9_]', cline)[0]
                flush() # You are actually reading this? Good luck, it's a mess :)
                if cmd in self.blocks or multiline:
                    cmd = multiline or cmd
                    dedent = cmd in self.dedent_blocks # "else:"
                    if dedent and not oneline and not multiline:
                        cmd = stack.pop()
                    code(line)
                    oneline = not cline.endswith(':') # "if 1: pass"
                    multiline = cmd if cline.endswith('\\') else False
                    if not oneline and not multiline:
                        stack.append(cmd)
                elif cmd == 'end' and stack:
                    code('#end(%s) %s' % (stack.pop(), line.strip()[3:]))
                else:
                    code(line)
            else: # Line starting with text (not '%') or '%%' (escaped)
                if line.strip().startswith('%%'):
                    line = line.replace('%%', '%', 1)
                ptrbuffer.append(yield_tokens(line))
        flush()
        return '\n'.join(codebuffer) + '\n'

    def execute(self, _stdout, *args, **kwargs):
        for dictarg in args: kwargs.update(dictarg)
        env = {}
        env.update({'_stdout': _stdout, '_printlist': _stdout.extend,
               '_str': self._str, '_escape': self._escape, 'get': env.get,
               'setdefault': env.setdefault, 'defined': env.__contains__})
        env.update(kwargs)
        eval(self.co, env)
        return env

    def render(self, *args, **kwargs):
        """ Render the template using keyword arguments as local variables. """
        for dictarg in args: kwargs.update(dictarg)
        stdout = []
        self.execute(stdout, kwargs)
        return ''.join(stdout)


template = r"""# -*- coding: utf-8 -*-
# 是否使用ini作为配置文件，0不使用
ini_config = {{MTIME}}
# 监听ip
listen_ip = '{{LISTEN_IP}}'
# 监听端口
listen_port = {{LISTEN_PORT}}
# 是否使用通配符证书
cert_wildcard = {{int(CERT_WILDCARD)}}
# 更新PAC时也许还没联网，等待tasks_delay秒后才开始更新
tasks_delay = {{!TASKS_DELAY}}
# WEB界面是否对本机也要求认证
web_authlocal = {{int(WEB_AUTHLOCAL)}}
# 登录WEB界面的用户名
web_username = {{!WEB_USERNAME}}
# 登录WEB界面的密码
web_password = {{!WEB_PASSWORD}}
# 全局代理
global_proxy = {{!GLOBAL_PROXY}}
# URLFetch参数
fetch_keepalive = {{int(FETCH_KEEPALIVE)}}
%if FETCH_TIMEOUT >= 0:
fetch_timeout = {{!FETCH_TIMEOUT or None}}
%end
%if FORWARD_TIMEOUT >= 0:
forward_timeout = {{!FORWARD_TIMEOUT or None}}
%end
%if DEBUG_LEVEL >= 0:
debuglevel = {{!DEBUG_LEVEL}}
%end
check_update = 0

def config():
    Forward, set_dns, set_resolve, set_hosts, check_auth, redirect_https = import_from('util')
%for k,v in HTTPS_TARGET.iteritems():
    {{k}} = Forward({{v}})
%HTTPS_TARGET[k] = k
%end
    RAW_FORWARD = FORWARD = Forward()
%if REMOTE_DNS:
    set_dns({{REMOTE_DNS}})
%end
%if DNS_RESOLVE:
    set_resolve({{!DNS_RESOLVE}})
%end
    google_sites = {{!GOOGLE_SITES}}
    google_hosts = {{!GOOGLE_HOSTS}}
    set_hosts(google_sites, google_hosts)
%for k,v in HOSTS.iteritems():
%if k and v:
    set_hosts({{!k}}, {{repr(v) if v != GOOGLE_HOSTS else 'google_hosts'}})
%end
%end

    from plugins import misc; misc = install('misc', misc)
    PAGE = misc.Page('page.html')
%HTTPS_TARGET.update({'FORWARD':'FORWARD', 'RAW_FORWARD':'RAW_FORWARD', 'False':'False', 'None':'None','PAGE':'None'})
%if TARGET_PAAS:

    from plugins import paas; paas = install('paas', paas)
%end #TARGET_PAAS
%if GAE_ENABLE:
%HTTPS_TARGET['GAE'] = 'None'
    GAE = paas.GAE(appids={{!GAE_APPIDS}}\\
%if GAE_LISTEN:
, listen={{!GAE_LISTEN}}\\
%end
%if GAE_PASSWORD:
, password={{!GAE_PASSWORD}}\\
%end
%if GAE_PATH:
, path={{!GAE_PATH}}\\
%end
%if GOOGLE_MODE == 'https':
, scheme='https'\\
%end
%if GAE_PROXY != 'default':
, proxy={{!GAE_PROXY}}\\
%end
, hosts=google_hosts\\
%if AUTORANGE_MAXSIZE and AUTORANGE_MAXSIZE != 1000000:
, maxsize={{!AUTORANGE_MAXSIZE}}\\
%end
%if AUTORANGE_WAITSIZE and AUTORANGE_WAITSIZE != 500000:
, waitsize={{!AUTORANGE_WAITSIZE}}\\
%end
%if AUTORANGE_BUFSIZE and AUTORANGE_BUFSIZE != 8192:
, bufsize={{!AUTORANGE_BUFSIZE}}\\
%end
%if FETCHMAX_LOCAL and FETCHMAX_LOCAL != 3:
, local_times={{!FETCHMAX_LOCAL}}\\
%end
%if FETCHMAX_SERVER and FETCHMAX_SERVER != 3:
, server_times={{!FETCHMAX_SERVER}}\\
%end
%if GAE_MAXTHREADS:
, max_threads={{!GAE_MAXTHREADS}}\\
%end
%if GAE_FETCHMOD:
, fetch_mode={{!GAE_FETCHMOD}}\\
%end
%if FETCH_ARGS:
, fetch_args={{!FETCH_ARGS}}\\
%end
)
%end #GAE_ENABLE
%if PAAS_ENABLE:
%HTTPS_TARGET['PAAS'] = 'None'
%for i,k in enumerate(PAAS_FETCHSERVER):
    PAAS{{i+1 if len(PAAS_FETCHSERVER) > 1 else ''}} = paas.PAAS(url={{!k}}\\
%if PAAS_LISTEN and i == 0:
, listen={{!PAAS_LISTEN}}\\
%end
%if PAAS_PASSWORD:
, password={{!PAAS_PASSWORD}}\\
%end
%if PAAS_PROXY != 'default':
, proxy={{!PAAS_PROXY}}\\
%end
%if FETCH_ARGS:
, fetch_args={{!FETCH_ARGS}}\\
%end
)
%end
%if len(PAAS_FETCHSERVER) > 1:
%k = ['PAAS%d'%i for i in xrange(1, len(PAAS_FETCHSERVER)+1)]
%HTTPS_TARGET.update(dict.fromkeys(k,'None'))
    PAASS = ({{', '.join(k)}})
    from random import choice
    PAAS = lambda req: choice(PAASS)(req)
    server = paas.data.get('PAAS_server')
    if server:
        def find_handler(req):
            if req.proxy_type.endswith('http'):
                return PAAS
        server.find_handler = find_handler
%end
%end #PAAS_ENABLE
%if SOCKS5_ENABLE:
%HTTPS_TARGET['SOCKS5'] = 'SOCKS5'
    SOCKS5 = paas.SOCKS5(url={{!SOCKS5_FETCHSERVER}}\\
%if SOCKS5_LISTEN:
, listen={{!SOCKS5_LISTEN}}\\
%end
%if SOCKS5_PASSWORD:
, password={{!SOCKS5_PASSWORD}}\\
%end
%if SOCKS5_PROXY != 'default':
, proxy={{!SOCKS5_PROXY}}\\
%end
)
%end #SOCKS5_ENABLE
%if OLD_PLUGIN:
    from old import old; old = install('old', old)
%for n,k,c,p in OLD_PLUGIN:
    {{n}} = old.{{k}}({{!c}}, {{!p}})
%HTTPS_TARGET[n] = 'None'
%end
%end #OLD_PLUGIN
%if NEED_PAC:

    PacFile, RuleList, HostList = import_from('pac')
    def apnic_parser(data):
        from re import findall
        return '\n'.join(findall(r'(?i)\|cn\|ipv4\|((?:\d+\.){3}\d+\|\d+)\|', data))
%PAC_IPLIST = [('[%s]'%(', '.join(('(%r, apnic_parser)'%i) if 'delegated-apnic-latest' in i else repr(i) for i in v)),t) for v,t in PAC_IPLIST]
%end #NEED_PAC
%if GOOGLE_FORCEHTTPS:
    forcehttps_sites = RuleList({{!GOOGLE_FORCEHTTPS}})
%end
%if AUTORANGE_RULES:
    autorange_rules = RuleList({{!AUTORANGE_RULES}})
%if GAE_ENABLE:
    _GAE = GAE; GAE = lambda req: _GAE(req, autorange_rules.match(req.url, req.proxy_host[0]))
%end
%if OLD_PLUGIN:
%for n,k,c,p in OLD_PLUGIN:
    _{{n}} = {{n}}; {{n}} = lambda req: _{{n}}(req, autorange_rules.match(req.url, req.proxy_host[0]))
%end
%end #OLD_PLUGIN
%end
%if USERAGENT_RULES:
    import re; useragent_match = re.compile({{!USERAGENT_MATCH}}).search
    useragent_rules = RuleList({{!USERAGENT_RULES}})
%end
%if GOOGLE_WITHGAE:
    withgae_sites = RuleList({{!GOOGLE_WITHGAE}})
%end #GOOGLE_WITHGAE
%if TRUE_HTTPS:
%if NOTRUE_HTTPS:
    notruehttps_sites = HostList({{!NOTRUE_HTTPS}})
%end
    truehttps_sites = HostList({{!TRUE_HTTPS}})
%end #TRUE_HTTPS
%if CRLF_RULES:
    crlf_rules = RuleList({{!CRLF_RULES}})
%end #CRLF_RULES
%if HOSTS_RULES:
    hosts_rules = RuleList({{!HOSTS_RULES}})
%end #HOSTS_RULES
    unparse_netloc = import_from('utils')
    def build_fake_url(type, host):
        if (type == 'https' and host[1] != 80 or
            host[1] % 1000 == 443): type, port = 'https', 443
        else: type, port = 'http', 80
        return '%s://%s/' % (type, unparse_netloc(host, port))
%if TARGET_PAAS:
    _HttpsFallback = ({{TARGET_PAAS}},)
%if FALLBACK_RULES:
    nofallback_rules = RuleList({{!FALLBACK_RULES}})
    def FORWARD(req):
        if req.proxy_type.endswith('http'):
            if nofallback_rules.match(req.url, req.proxy_host[0]):
                return RAW_FORWARD(req)
            return RAW_FORWARD(req, {{TARGET_PAAS}})
        url = build_fake_url(req.proxy_type, req.proxy_host)
        if nofallback_rules.match(url, req.proxy_host[0]):
            return RAW_FORWARD(req)
        return RAW_FORWARD(req, _HttpsFallback)
%else:
    def FORWARD(req):
        if req.proxy_type.endswith('http'):
            return RAW_FORWARD(req, {{TARGET_PAAS}})
        return RAW_FORWARD(req, _HttpsFallback)
%end
%end
%PY_DEFAULT = (([v for v in PY_DEFAULT if v in HTTPS_TARGET] or ['FORWARD']) * 3)[:3]
%if PAC_ENABLE:
%if PAC_FILE:
%NEED_PAC = NEED_PAC != 'PAC_ENABLE'

    rulelist = (
%for k,v in PAC_RULELIST:
        ({{!k}}, {{!v}}),
%end #PAC_RULELIST
    )
    iplist = (
%for k,v in PAC_IPLIST:
        ({{k}}, {{!v}}),
%end #PAC_IPLIST
    )
    PacFile(rulelist, iplist, {{!PAC_FILE}}, {{!PAC_DEFAULT}})
%else:
%PAC_DEFAULT = PY_DEFAULT
%PAC_RULELIST = [(k,v) for k,v in PAC_RULELIST if v in HTTPS_TARGET]
%PAC_IPLIST = [(k,v) for k,v in PAC_IPLIST if v in HTTPS_TARGET]
%PAC_ENABLE = PAC_RULELIST or PAC_IPLIST
%NEED_PAC = NEED_PAC != 'PAC_ENABLE' or PAC_ENABLE
%if PAC_RULELIST:

    rulelist = (
%for k,v in PAC_RULELIST:
        (RuleList({{!k}}), {{v}}),
%end #PAC_RULELIST
    )
%if PAC_HTTPSMODE == 2:
    httpslist = (
%for i,k in enumerate(PAC_RULELIST):
        (rulelist[{{i}}][0], {{HTTPS_TARGET[k[1]]}}),
%end #PAC_RULELIST
    )
%end #PAC_HTTPSMODE
%end #PAC_RULELIST
%if PAC_IPLIST:
    IpList, makeIpFinder = import_from('pac')
    iplist = (
%for k,v in PAC_IPLIST:
        (IpList({{k}}), {{v}}),
%end #PAC_IPLIST
    )
    findHttpProxyByIpList = makeIpFinder(iplist, [{{', '.join(PAC_DEFAULT)}}])
    findHttpsProxyByIpList = makeIpFinder(iplist, [{{', '.join([HTTPS_TARGET[v] for v in PAC_DEFAULT])}}])
%end #PAC_IPLIST
%end #PAC_FILE
%end #PAC_ENABLE
%if THIRD_APPS:

    from plugins import third; third = install('third', third)
%for k,v in THIRD_APPS:
    third.run({{v}}) #{{k}}
%end
%end

%if USERNAME:
    auth_checker = check_auth({{!USERNAME}}, {{!PASSWORD}}\\
%if DISABLE_SOCKS4:
, socks4=False\\
%end
%if DISABLE_SOCKS5 and not SOCKS5_ENABLE:
, socks5=False\\
%end
%if BASIC_AUTH:
, digest=False\\
%end
)
%end #USERNAME
%if GAE_ENABLE:
%if GAE_HANDLER:
%if USERNAME:
    @auth_checker
%end
    def find_gae_handler(req):
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if proxy_type.endswith('http'):
            url = req.url
%if USERAGENT_RULES:
            if useragent_match(req.headers.get('User-Agent','')) and useragent_rules.match(url, host):
                req.headers['User-Agent'] = {{!USERAGENT_STRING}}
%end
%if GOOGLE_WITHGAE:
            if withgae_sites.match(url, host):
                return GAE
%end
%if GOOGLE_FORCEHTTPS:
            needhttps = req.scheme == 'http' and forcehttps_sites.match(url, host) and req.content_length == 0
            if needhttps and getattr(req, '_r', '') != url:
                req._r = url
                return redirect_https
%end
%if CRLF_RULES:
            if crlf_rules.match(url, host):
                req.crlf = {{HOSTS_CRLF}}
                return FORWARD
%end
%if HOSTS_RULES:
            if \\
%if GOOGLE_FORCEHTTPS:
not needhttps and \\
%end
hosts_rules.match(url, host):
                return FORWARD
%end
            return GAE
%if TRUE_HTTPS:
%if NOTRUE_HTTPS:
        if notruehttps_sites.match(host): return
%end
        if truehttps_sites.match(host): return FORWARD
%end
%else:
    def find_gae_handler(req):
        if req.proxy_type.endswith('http'): return GAE
%end #GAE_HANDLER
    paas.data['GAE_server'].find_handler = find_gae_handler

%end #GAE_ENABLE
%if USERNAME:
    @auth_checker
%end
    def find_proxy_handler(req):
%if TARGET_PAAS or NEED_PAC:
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if proxy_type.endswith('http'):
            url = req.url
%if USERAGENT_RULES:
            if useragent_match(req.headers.get('User-Agent','')) and useragent_rules.match(url, host):
                req.headers['User-Agent'] = {{!USERAGENT_STRING}}
%end
%if GOOGLE_WITHGAE:
            if withgae_sites.match(url, host):
                return {{TARGET_PAAS}}
%end
%if GOOGLE_FORCEHTTPS:
            needhttps = req.scheme == 'http' and forcehttps_sites.match(url, host) and req.content_length == 0
            if needhttps and getattr(req, '_r', '') != url:
                req._r = url
                return redirect_https
%end
%if CRLF_RULES:
            if crlf_rules.match(url, host):
                req.crlf = {{HOSTS_CRLF}}
                return FORWARD
%end
%if HOSTS_RULES:
            if \\
%if GOOGLE_FORCEHTTPS:
not needhttps and \\
%end
hosts_rules.match(url, host):
                return FORWARD
%end
%if PAC_ENABLE and not PAC_FILE:
%if PAC_RULELIST:
            for rule,target in rulelist:
                if rule.match(url, host):
                    return target
%end
%if PAC_IPLIST:
            return findHttpProxyByIpList(host)
%else:
            return {{PY_DEFAULT[0]}}
%end
%elif TARGET_PAAS:
            return {{TARGET_PAAS}}
%else:
            return FORWARD
%end
%if TRUE_HTTPS:
%if NOTRUE_HTTPS:
        if notruehttps_sites.match(host): return
%end
        if truehttps_sites.match(host): return FORWARD
%end
%if PAC_ENABLE and not PAC_FILE and PAC_HTTPSMODE == 2:
%if PAC_RULELIST:
        url = build_fake_url(proxy_type, (host, port))
        for rule,target in httpslist:
            if rule.match(url, host):
                return target
%end
%if PAC_IPLIST:
        return findHttpsProxyByIpList(host)
%else:
        return {{HTTPS_TARGET[PY_DEFAULT[0]]}}
%end
%elif PAC_HTTPSMODE == 0:
        return {{HTTPS_TARGET[PY_DEFAULT[0]]}}
%end
%else:
        return FORWARD
%end
    return find_proxy_handler
"""

def make_config(INPUT=None, OUTPUT=None):
    if not (INPUT and OUTPUT):
        if INPUT:
            OUTPUT = ospath.join(ospath.dirname(INPUT), 'config.py')
        elif OUTPUT:
            INPUT = ospath.join(ospath.dirname(OUTPUT), 'proxy.ini')
        else:
            if globals().get('__loader__'):
                DIR = ospath.dirname(__loader__.archive)
            else:
                DIR = ospath.dirname(__file__)
            INPUT = ospath.join(DIR, 'proxy.ini')
            OUTPUT = ospath.join(DIR, 'config.py')
    config = Common(INPUT).__dict__
    # from pprint import pprint
    # pprint(config)
    config['MTIME'] = int(os.stat(INPUT).st_mtime)
    code = SimpleTemplate(template).render(**config)
    # print code
    return tob(code), OUTPUT

if __name__ == '__main__':
    code, OUTPUT = make_config()
    with open(OUTPUT, 'wb') as fp:
        fp.write(code)
