#! /usr/bin/python
# -*- coding: utf-8 -*-

import io, re, ConfigParser
from model import Rule
from model import DNSItem

class HostsParser:

    RULE_REGEX = re.compile(r"^(@([1-5])@ )?(((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))|(\w)*?) (.*?)$", re.IGNORECASE)

    def __init__(self, filename):
        hosts_content = []
        config = ConfigParser.ConfigParser()
        with open(filename, 'r') as conf_file:
            config_content = conf_file.readline()
            while True:
                line = conf_file.readline()
                if line.strip() == "[hosts]": break
                config_content += line
            hosts_content = conf_file.readlines()
            config.readfp(io.BytesIO(config_content))
        self._hosts_dic = {}
        self.IP = config.get("listen", 'ip')
        self.PORT = config.getint("listen", 'port')
        for host_line in hosts_content:
            if host_line.startswith("!") or host_line in ("\n", "\r\n"): continue
            rule_matched_content = HostsParser.RULE_REGEX.search(host_line)
            if rule_matched_content is None: continue
            priority = rule_matched_content.group(2)
            ip_type = Rule.TYPE_REQUEST if rule_matched_content.group(4) is None else Rule.TYPE_A
            ip_list = rule_matched_content.group(3) if ip_type == Rule.TYPE_A else config.get("DNS Config", rule_matched_content.group(3))
            ip_list = map(lambda str:str.strip(), ip_list.split(","))
            rule_text = rule_matched_content.group(6)
            rule_type = Rule.REGEX_RULE if rule_text.startswith('/') and rule_text.endswith('/') else Rule.RAW_RULE
            rule = Rule(priority, ip_list, ip_type, rule_text, rule_type)
            rule_digest = rule.get_digest()
            self._hosts_dic.setdefault(rule_digest, [])
            self._hosts_dic[rule_digest].append(rule)
        self._all_dns = DNSItem("all_dns", [])
        self._dns_dict = {}
        for item in config.items("DNS Config"):
            self._dns_dict[item[0]] = DNSItem(item[0], map(lambda str:str.strip(), item[1].split(",")))
            map(lambda str:self._all_dns._dns_list.append(str), self._dns_dict[item[0]]._dns_list)

    def get_all_dns_list(self):
        return self._all_dns._dns_list

    def get_dns_item(self, item_name):
        return None if item_name not in self._dns_dict.keys() else self._dns_dict[item_name]

    def get_hosts_dic(self):
        return self._hosts_dic

    def match(self, domain):
        candidate_list = []
        for key, value in self._hosts_dic.iteritems():
            if key is None or key in domain:
                candidate_list += value
        match_list = filter(lambda rule: rule.match(domain), candidate_list)
        if match_list == []: return None
        return min(match_list, key = lambda rule: rule._priority)

if __name__ == '__main__':
    import os, sys
    sys.path.append(os.getcwd())
    parser = HostsParser('hosts.ini')
    print parser.get_all_dns_list()
    print parser.get_dns_item("preferred_dns")
    print parser._dns_dict
    print parser._hosts_dic