from scapy.all import DNSQR, NoPayload
from classifiers import classify_pkt

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
            self.IP = [line.strip('\n') for line in IP_file]

        if signature_file is not None:
            # decode('string_escape') enables the user to write
            # hex characters as plaintext
            #TODO Be sure to document that the escaped x is necessary! \xHH
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
        payload = pkt[TCP].payload.load
        for signature in self.signatures:
            if signature in payload:
                return classify_pkt(pkt, 'ILLEGAL_SIGNATURE',
                        payload=payload, rule=rule)
        return None

    def filter_by_URL(self, pkt):
        # Assume unencrypted HTTP packet
        #TODO
        if match:
            return classify_pkt(pkt, 'ILLEGAL_URL', rule=rule)
        return None

    def filter_by_IP(self, pkt):
        #TODO
        if match:
            return classify_pkt(pkt, 'ILLEGAL_IP', rule=rule)
        return None
