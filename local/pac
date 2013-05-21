# -*- coding: utf-8 -*-
listen_port = 0
def config():
    import sys
    ini = 'proxy.ini'
    files = sys.argv[2:]
    if files and files[0].endswith('.ini'):
        ini = files[0]; files = files[1:]
    if files:
        from make_config import Common
        from os.path import dirname, join
        ini = Common(join(dirname(config['__file__']), ini))
        ini.PAC_FILE = files; ini.parse_pac_config()
        def apnic_parser(data):
            from re import findall
            return '\n'.join(findall(r'(?i)\|cn\|ipv4\|((?:\d+\.){3}\d+\|\d+)\|', data))
        ini.PAC_IPLIST = [([(i, apnic_parser) if 'delegated-apnic-latest' in i
            else i for i in v],t) for v,t in ini.PAC_IPLIST]
        try:
            del httpd.__class__.server_address
        except AttributeError:
            pass
        httpd.server_address = ini.LISTEN_IP or '0.0.0.0', ini.LISTEN_PORT
        set_hosts = import_from('util')
        set_hosts(ini.GOOGLE_SITES, ini.GOOGLE_HOSTS)
        for k,v in ini.HOSTS.iteritems():
            if k and v: set_hosts(k, v)
        PacFile = import_from('pac')
        PacFile(ini.PAC_RULELIST, ini.PAC_IPLIST, ini.PAC_FILE, ini.PAC_DEFAULT)
