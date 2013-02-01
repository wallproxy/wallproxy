# -*- coding: utf-8 -*-

def dns_proxy():

    _temp = __import__('DNS Proxy', globals(), locals(), ['dns_proxy'], -1)
    dns_proxy = _temp.dns_proxy

    def wp_start():
        import config
        dns_proxy.wp_start(config.dns_config_file)

    globals().update(start = wp_start)