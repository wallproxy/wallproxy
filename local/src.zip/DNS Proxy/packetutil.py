#! /usr/bin/python
# -*- coding: utf-8 -*-

import binascii, io, struct

convert_ip_to_bytes = lambda ip: reduce(lambda content, current: content + struct.pack("!B", int(current)), ip.split('.'), "")

convert_ip_from_bytes = lambda ipv4: ".".join([str(int(binascii.hexlify(ipv4[i]), 16)) for i in xrange(0, 4)])

convert_ipv6_from_bytes = lambda ipv6: ":".join(["0" if ipv6[i: i + 2] == "\x00\x00" else binascii.hexlify(ipv6[i: i + 2]).lstrip("0") for i in xrange(0, 16, 2)])

hex2int = lambda num: int(binascii.hexlify(num), 16)

hex2bin = lambda num: "0" * (len(num) * 8 - len(bin(int(binascii.hexlify(num), 16))[2:])) + "%s" % (bin(int(binascii.hexlify(num), 16))[2:])

class DNSPacketUtil:

    DNS_QTYPE = {
        "\x00\x01": "A", "\x00\x02": "NS", "\x00\x05": "CNAME", "\x00\x06": "SOA",
        "\x00\x0b": "WKS", "\x00\x0c": "PTR", "\x00\x0f": "MX", "\x00\x10": "TXT",
        "\x00\x1C": "AAAA", "\x00\xFC": "AXFR", "\x00\xFF": "ANY", "\x00!": "SRV"
    }

    DNS_QCLASS = {
        "\x00\x01": "The Internet(IN)"
    }

    DNS_QR = {
        "0": "Query", "1": "Response"
    }

    DNS_OPCODE = {
        "0000": "A standard query (QUERY)",
        "0001": "An inverse query (IQUERY)",
        "0010": "A server status request (STATUS)"
    }

    DNS_RCODE = {
        "0000": "No error condition",
        "0001": "Format error",
        "0010": "Server failure",
        "0011": "Name Error",
        "0100": "Not Implemented",
        "0101": "Refused"
    }

    @classmethod
    def get_dns_host(cls, request = "", inputIO = "", complete_data = ""):
        hostname = ""
        with io.BytesIO(request) as requestIO:
            if inputIO != "": requestIO = inputIO
            next_length = struct.unpack("!B", requestIO.read(1))[0]
            while next_length:
                hostname += requestIO.read(next_length) + '.'
                next_length_s = requestIO.read(1)
                next_length = struct.unpack("!B", next_length_s)[0]
                if hex2bin(next_length_s)[0:2] == "11":
                    requestIO.seek(-1, io.SEEK_CUR)
                    off_length = int(hex2bin(requestIO.read(2))[2:], 2)
                    hostname += cls.get_dns_host(request = complete_data[off_length:], complete_data = complete_data)[0] + "."
                    break
            return (hostname[0:-1], requestIO.tell() + 1)

    @classmethod
    def rr_reslover(cls, inputIO, complete_data):
        next_length_s = inputIO.read(2)
        if hex2bin(next_length_s)[0:2] == "11":
            off_length = int(hex2bin(next_length_s)[2:], 2)
            hostname = cls.get_dns_host(request = complete_data[off_length:], complete_data = complete_data)[0]
        else:
            inputIO.seek(-2, io.SEEK_CUR)
            hostname = cls.get_dns_host(inputIO = inputIO, complete_data = complete_data)[0]
        r_type  = cls.DNS_QTYPE[inputIO.read(2)]
        r_class = cls.DNS_QCLASS[inputIO.read(2)]
        ttl     = struct.unpack("!I", inputIO.read(4))[0]
        rdlen   = struct.unpack("!H", inputIO.read(2))[0]
        return {
            "NAME":     hostname,
            "TYPE":     r_type,
            "CLASS":    r_class,
            "TTL":      ttl,
            "RDLENGTH": rdlen,
            "RDATA":    cls.rdata_reslover(r_type, rdlen, inputIO, complete_data)
        }

    @classmethod
    def rdata_reslover(cls, type, rdlength, inputIO, complete_data):
        if type == "A":
            return convert_ip_from_bytes(inputIO.read(4))
        elif type == "CNAME":
            hostname = ""
            next_length_s = inputIO.read(1)
            while hex2bin(next_length_s)[0:2] != "11":
                #inputIO.seek(-2, io.SEEK_CUR)
                length = struct.unpack("!B", next_length_s)[0]
                if length == 0:
                    hostname = hostname[0:-1]
                    break
                hostname += inputIO.read(length) + "."
                next_length_s = inputIO.read(1)
            else:
                next_length_s += inputIO.read(1)
                hostname += cls.get_dns_host(request = complete_data[int(hex2bin(next_length_s)[2:], 2):], complete_data = complete_data)[0]
        elif type == "AAAA":
            return convert_ipv6_from_bytes(inputIO.read(16))
        else:
            return inputIO.read(rdlength)

    @classmethod
    def get_qtype(cls, request):
        return cls.DNS_QTYPE[request[-4:-2]]

    @staticmethod
    def pack_dns_response(request, ip_list):
        with io.BytesIO() as bytesIO:
            bytesIO.write(request[0:2] + "\x81\x80\x00\x01")        # Trans_ID, Query, RD, RA, One Question
            bytesIO.write(struct.pack("!HHH", len(ip_list), 0, 0))  # Num of answer_rr(s), 0 authority_rr, 0 additional_rr
            bytesIO.write(request[12:])                             # Copy of queries
            for ip in ip_list:
                bytesIO.write("\xC0\x0C\x00\x01\x00\x01")           # Name ptr = 0xC00C, type = A(0x0001), class = IN(0x0001)
                bytesIO.write(struct.pack("!IH", 3600, 4))          # TTL = 3600s, RDLENGTH = 4
                bytesIO.write(convert_ip_to_bytes(ip))              # RDATA = IP
            return bytesIO.getvalue()

    @classmethod
    def unpack_dns_header(cls, header):
        header_struct = {}
        with io.BytesIO(header) as headerIO:
            trans_id = headerIO.read(2)
            header_syntax = hex2bin(headerIO.read(2))
            header_struct["Trans_ID"]   = trans_id,
            header_struct["QR"]         = cls.DNS_QR[header_syntax[0]],
            header_struct["OPCODE"]     = cls.DNS_OPCODE[header_syntax[1:5]],
            header_struct["AA"]         = header_syntax[5],
            header_struct["TC"]         = header_syntax[6],
            header_struct["RD"]         = header_syntax[7],
            header_struct["RA"]         = header_syntax[8],
            header_struct["Z"]          = header_syntax[9:12],
            header_struct["RCODE"]      = cls.DNS_RCODE[header_syntax[12:]],
            header_struct["QDCOUNT"],\
            header_struct["ANCOUNT"],\
            header_struct["NSCOUNT"],\
            header_struct["ARCOUNT"]    = struct.unpack("!HHHH", headerIO.read(8))
        return header_struct

    @classmethod
    def unpack_dns_request(cls, request):
        dns_struct = {"Header": {}, "Question": {}}
        dns_struct["Header"] = cls.unpack_dns_header(request[0:12])
        with io.BytesIO(request[12:]) as requestIO:
            dns_struct["Question"]["NAME"] = []
            for i in xrange(dns_struct["Header"]["QDCOUNT"]):
                dns_struct["Question"]["NAME"].append(cls.get_dns_host(inputIO = requestIO, complete_data = request)[0])
            dns_struct["Question"]["QTYPE"] = cls.DNS_QTYPE[requestIO.read(2)]
            dns_struct["Question"]["QCLASS"] = cls.DNS_QCLASS[requestIO.read(2)]
        return dns_struct

    @classmethod
    def unpack_dns_response(cls, response):
        dns_struct = {"Header": {}, "Question": {}, "Answer": [], "Authority": [], "Additional": []}
        dns_struct["Header"] = cls.unpack_dns_header(response[0:12])
        with io.BytesIO(response[12:]) as responseIO:
            dns_struct["Question"]["NAME"] = []
            for i in xrange(dns_struct["Header"]["QDCOUNT"]):
                dns_struct["Question"]["NAME"].append(cls.get_dns_host(inputIO = responseIO, complete_data = response)[0])
            dns_struct["Question"]["QTYPE"] = cls.DNS_QTYPE[responseIO.read(2)]
            dns_struct["Question"]["QCLASS"] = cls.DNS_QCLASS[responseIO.read(2)]
            for i in xrange(dns_struct["Header"]["ANCOUNT"]):
                dns_struct["Answer"].append(cls.rr_reslover(responseIO, response))
            for i in xrange(dns_struct["Header"]["NSCOUNT"]):
                dns_struct["Authority"].append(cls.rr_reslover(responseIO, response))
            for i in xrange(dns_struct["Header"]["ARCOUNT"]):
                dns_struct["Additional"].append(cls.rr_reslover(responseIO, response))
            if dns_struct["Answer"] == []: dns_struct["Answer"] = [{"NAME":"", "TYPE":"","CLASS":"","TTL":"","RDLENGTH":"","RDATA":""}]
            if dns_struct["Authority"] == []: dns_struct["Authority"] = [{"NAME":"", "TYPE":"","CLASS":"","TTL":"","RDLENGTH":"","RDATA":""}]
            if dns_struct["Additional"] == []: dns_struct["Additional"] = [{"NAME":"", "TYPE":"","CLASS":"","TTL":"","RDLENGTH":"","RDATA":""}]
            return dns_struct
