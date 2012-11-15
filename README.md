wallproxy
===
New version of wallproxy, a general purpose proxy framework in Python. It can run on Python 2.5/2.6/2.7, and an Python environment with ssl, pyOpenSSL, gevent is recommended.

How to run it?
---
```
./startup.py [config_file]
```
The default config_file is `config.py`, if `ini_config` is defined in config_file and does not equal 0 or config_file is missing, wallproxy will generate config_file from `proxy.ini` under the same directory.

wallproxy can serve HTTP/HTTPS/SOCKS4/SOCKS5 proxy on single port, here is an example config_file:
```python
listen_ip = '0.0.0.0'
listen_port = 8086
def config():
    # digest_auth = import_from('util')
    # def check_auth(username, password, socks4=True, socks5=True, digest=True):
        # socks5_userid = (username, password)
        # socks4_userid = '%s:%s' % socks5_userid
        # if not password:
            # socks4_userid = username
            # def http_auth(req): pass
        # elif digest:
            # def http_auth(req):
                # return digest_auth(req, username, password)
        # else:
            # basic_userid = 'Basic ' + b64encode(socks4_userid)
            # def http_auth(req):
                # if req.userid != basic_userid:
                    # return 'Basic realm="wallproxy Proxy Authenticate"'
        # if not socks4: socks4_userid = False
        # if not socks5: socks5_userid = False
        # def decorator(func):
            # def wrapper(req):
                # proxy_type = req.proxy_type
                # if proxy_type == 'socks4':
                    # if req.userid != socks4_userid:
                        # return False
                # elif proxy_type == 'socks5':
                    # if req.userid != socks5_userid:
                        # return False
                # elif proxy_type in ('https', 'http'):
                    # auth = http_auth(req)
                    # if auth: return auth
                # req.userid = None
                # return func(req)
            # return wrapper
        # return decorator

    # def redirect_https(req):
        # return req.send_error(301, '',
            # 'Location: %s\r\n' % req.url.replace('http://', 'https://', 1))

    Forward, check_auth, redirect_https = import_from('util')
    DIRECT = Forward(None)
    PROXY1 = Forward('http://10.0.0.100:8080')
    PROXY2 = Forward('https://user:pwd@10.0.0.100:8081')
    PROXY3 = Forward('hosts://www.google.com:80')
    PROXY4 = Forward('socks4://10.0.0.100:8082')
    PROXY5 = Forward('socks5://10.0.0.100:8083/?dns=1')
    PROXY6 = Forward(('socks5://10.0.0.100:8083', 'http://10.0.0.100:8080'))

    @check_auth('user', 'pwd')
    def find_proxy_handler(req):
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if host == 'type-switch-site':
            return None # socks->http, https->http, http->web
        elif host == 'forbid-site':
            return False
        if proxy_type.endswith('http'): # socks2http, https2http, http
            if req.url == 'http://mail.qq.com/': return redirect_https
            if req.command == 'GET': return PROXY1
            if 'MSIE' in req.headers.get('User-Agent', ''): return PROXY2
            if host == 'www.baidu.com' and port == 80: return PROXY3
            return DIRECT
        elif proxy_type == 'https':
            if host == 'www.bing.com': return PROXY4
            # return None
        elif proxy_type == 'socks4':
            return PROXY5
        elif proxy_type == 'socks5':
            if req.command != 1: return False
            return PROXY6

    return find_proxy_handler
```