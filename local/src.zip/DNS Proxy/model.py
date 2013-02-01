#! /usr/bin/python
# -*- coding: utf-8 -*-

import re

class Rule:

    DIGEST_REGEX = re.compile('[A-Za-z0-9-\.]{3,}', re.IGNORECASE)
    (RAW_RULE ,REGEX_RULE, PRIORITY, PRIORITY_HIGH, PRIORITY_MEDIUM_HIGH, PRIORITY_MEDIUM,
        PRIORITY_MEDIUM_LOW, PRIORITY_LOW, TYPE_A, TYPE_REQUEST) = range(10)

    def __init__(self, priority, ip_list, ip_type, raw_rule, rule_type):
        self._priority = Rule.PRIORITY if priority is None else priority
        self._rule_type = rule_type
        if self._rule_type == Rule.RAW_RULE:
            self._raw_rule = raw_rule
            converted_rule = "^" + raw_rule.replace("*", "[A-Za-z0-9-\.]+").replace("?", "[A-Za-z0-9-]+").replace(".", "\.") + "$"
            self._regex_rule = re.compile(converted_rule, re.IGNORECASE)
        elif self._rule_type == Rule.REGEX_RULE:
            self._raw_rule = raw_rule
            self._regex_rule = re.compile(raw_rule[1:-1], re.IGNORECASE)
        else:
            raise TypeError,'Undefined Rule Type'
        self._ip_type = ip_type
        self._ip_list = ip_list
        if self._priority == Rule.PRIORITY:
            if self._ip_type == Rule.TYPE_REQUEST:
                self._priority = Rule.PRIORITY_MEDIUM_LOW
            elif self._rule_type == Rule.REGEX_RULE or "*" in self._raw_rule or "?" in self._raw_rule:
                self._priority = Rule.PRIORITY_MEDIUM
            else:
                self._priority = Rule.PRIORITY_MEDIUM_HIGH

    def get_digest(self):
        if self._rule_type == Rule.REGEX_RULE: return None
        digest_list = Rule.DIGEST_REGEX.findall(self._raw_rule)
        if len(digest_list) == 0: return None
        if len(digest_list) == 1: return digest_list[0]
        return max(digest_list, key = len)

    def match(self, domain):
        return False if self._regex_rule.search(domain) is None else True

    def __str__(self):
        return str(self._priority) + str(self._ip_list) + str(self._ip_type) + str(self._raw_rule) + str(self._rule_type)

class DNSItem:

    def __init__(self, name, dns_list):
        self._name = name
        self._dns_list = dns_list