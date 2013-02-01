#! /usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'cmF0c3VubnlAZ21haWwuY29t\n'.decode('base64')
__version__ = '0.0.1'
__DEBUG__ = True

import os, struct, socket, thread
from SocketServer import *
from hostsutil import HostsParser
from packetutil import DNSPacketUtil
from model import Rule, DNSItem

class LocalThreadingDNSServer(ThreadingMixIn, UDPServer):
    def __init__(self, addr, handler):
        UDPServer.__init__(self, addr, handler)

class DNSRequestHandler(BaseRequestHandler):
    daemon_threads = True
    allow_reuse_address = True

    def handle(self):
        req_socket = self.request[1]
        data = self.request[0]
        host_name = DNSPacketUtil.get_dns_host(data[12:])[0]
        req_struct = DNSPacketUtil.unpack_dns_request(data)
        print "DNS Request: Question:%s, Type:%s" % (req_struct["Question"]["NAME"], req_struct["Question"]["QTYPE"])
        tcp_response_data = ""
        rule = hosts_content.match(host_name)
        if rule is None:
            tcp_response_data = self.getResponse(data, hosts_content.get_all_dns_list())
        elif rule._ip_type == Rule.TYPE_REQUEST:
            tcp_response_data = self.getResponse(data, rule._ip_list)
        elif rule._ip_type == Rule.TYPE_A and (DNSPacketUtil.get_qtype(data) in ("A", "CNAME")):
            tcp_response_data = DNSPacketUtil.pack_dns_response(data, rule._ip_list)
        else:
            tcp_response_data = self.getResponse(data, hosts_content.get_all_dns_list())
        try:
            dns_response_struct = DNSPacketUtil.unpack_dns_response(tcp_response_data)
        except Exception, e:
            print e
        #print "DNS Response: Question: %s, Type:%s, Answer:%s" % (dns_response_struct["Question"]["NAME"], dns_response_struct["Answer"][0]["TYPE"], dns_response_struct["Answer"][0]["NAME"])
        #print dns_response_struct["Answer"]
        req_socket.sendto(tcp_response_data, self.client_address)

    def getResponse(self, data, dns_ip_list):
        send_buffer = struct.pack('!h', len(data)) + data
        socket.setdefaulttimeout(4)
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for dns_ip in dns_ip_list:
            try:
                tcp_socket.connect((dns_ip, 53))
                tcp_socket.sendall(send_buffer)
                tcp_data = tcp_socket.recv(8192)
            except socket.timeout, e:
                if tcp_socket: tcp_socket.close()
                tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                continue
            else:
                if tcp_socket: tcp_socket.close()
                return tcp_data[2:]
        if tcp_socket: tcp_socket.close()
        return ""

def launcher(host_file_loc = "hosts.ini"):
    global hosts_content
    hosts_content = HostsParser(host_file_loc)
    local_server = LocalThreadingDNSServer((hosts_content.IP, hosts_content.PORT), DNSRequestHandler)
    local_server.serve_forever()
    local_server.shutdown()

def wp_start(host_file_loc):
    print "Initilizing DNS Proxy..."
    thread.start_new_thread(launcher,(host_file_loc,))
    print "DNS Proxy Started Successful!"

if __name__ == "__main__":
    launcher()