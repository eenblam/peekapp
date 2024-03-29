# peekapp/blacklist.py

from scapy.all import DNSQR, NoPayload, IP, TCP, UDP
from util import classify_pkt

class Blacklist(object):
    def __init__(self, domain_file=None,
                URL_file=None,
                IP_file=None,
                signature_file=None):

        self.domains = []
        self.URLs = []
        self.IPs = []
        self.signatures = []

        if domain_file is not None:
            self.domains = [line.strip('\n') for line in domain_file]

        if URL_file is not None:
            self.URLs = [line.strip('\n') for line in URL_file]

        if IP_file is not None:
            self.IPs = [line.strip('\n') for line in IP_file]

        if signature_file is not None:
            # decode('string_escape') enables the user to write
            # arbitrary bytes in plaintext as escaped, two-digit hex
            lines = [line.strip('\n').decode('string_escape')
                    for line in signature_file]
            self.signatures = lines

    def filter_by_domains(self, pkt):
        # Assume pkt is of correct format
        domain = pkt[DNSQR].qname.rstrip('.')
        domain_parts = domain.split('.')[::-1]
        # Forward pkt, classified by first rule matched
        for rule in self.domains:
            # Split on period, then match last elements of split
            rule_parts = rule.split('.')[::-1]
            matched_parts = zip(rule_parts, domain_parts)
            match_equalities = (x==y for x,y in matched_parts)
            match = reduce(lambda x,y: x and y, match_equalities)
            if match:
                return classify_pkt(pkt, 'ILLEGAL_DOMAIN',
                        payload=domain, rule=rule)
        return None

    def filter_by_signatures(self, pkt):
        if pkt.haslayer(TCP):
            payload = str(pkt[TCP])
        elif pkt.haslayer(UDP):
            payload = str(pkt[UDP])
        else:
            return

        for signature in self.signatures:
            if signature in payload:
                return classify_pkt(pkt, 'ILLEGAL_SIGNATURE',
                        payload=payload.encode('string_escape'),
                        rule=signature.encode('string_escape'))
        return None

    def filter_by_URL(self, pkt):
        # Assume unencrypted HTTP packet
        try:
            raw_load = pkt.payload.load
        except AttributeError:
            return

        first = raw_load.split('\r\n')[0].strip()

        try:
            # RFC2616
            # https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5
            method, identifier, version = first.split()
        except ValueError:
            # Wrong number of values to unpack; mal-formed HTTP at best
            return

        if method in ['GET', 'HEAD', 'POST', 'PUT',
                'OPTIONS', 'DELETE', 'TRACE', 'CONNECT']:
            for rule in self.URLs:
                if rule in identifier:
                    return classify_pkt(pkt, 'ILLEGAL_URL',
                            payload=identifier, rule=rule)
        return None

    def filter_by_IP(self, pkt):
        if pkt.haslayer(UDP):
            try:
                payload = pkt[UDP][DNSQR].payload.load
            except AttributeError, IndexError:
                payload = NoPayload()
        elif pkt.haslayer(TCP):
            try:
                payload = pkt[TCP].payload.load
            except IndexError:
                payload = NoPayload()
        else:
            #TODO Expand on this, but isolate this mess someplace else
            payload = NoPayload()

        src, dst = pkt[IP].src, pkt[IP].dst
        for ip in self.IPs:
            if ip == src or ip == dst:
                return classify_pkt(pkt, 'ILLEGAL_IP', payload=payload, rule=ip)
        return None
