# -*- coding: utf-8 -*-
listen_port = 0
def config():
    import sys
    files = sys.argv[2:]
    if files:
        from make_config import Common
        from os.path import dirname, join
        ini = Common(join(dirname(config['__file__']), 'proxy.ini'))
        ini.PAC_FILE = files; ini.parse_pac_config()
        try:
            del httpd.__class__.server_address
        except AttributeError:
            pass
        httpd.server_address = ini.LISTEN_IP or '0.0.0.0', ini.LISTEN_PORT
        set_hosts = import_from('util')
        set_hosts('.googlecode.com', ini.GOOGLE_HOSTS)
        PacFile = import_from('pac')
        PacFile(ini.PAC_RULELIST, ini.PAC_IPLIST, ini.PAC_FILE, ini.PAC_DEFAULT)
