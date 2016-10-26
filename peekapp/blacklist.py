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
            self.load_signatures(domain_file)

        if URL_file is not None:
            self.load_URL_blacklist(URL_file)

        if IP_file is not None:
            self.load_IP_blacklist(IP_file)

        if signature_file is not None:
            self.load_signatures(signature_file)

    def load_domain_blacklist(self, filename):
        with open(filename, 'r') as f:
            self.domains = [line.strip('\n') for line in f]

    def load_signatures(self, filename):
        with open(filename, 'r') as f:
            # decode('string_escape') enables the user to write
            # hex characters as plaintext
            #TODO Be sure to document that the escaped x is necessary! \xHH
            lines = [line.strip('\n').decode('string_escape')
                    for line in f]
        self.signatures = lines

    def load_URL_blacklist(self, filename):
        with open(filename, 'r') as f:
            self.URLs = [line.strip('\n') for line in f]

    def load_IP_blacklist(self, filename):
        with open(filename, 'r') as f:
            self.IPs = [line.strip('\n') for line in f]

#def classify_pkt(pkt, traffic_type, rule=None, payload=NoPayload):
    def filter_by_domains(self, pkt):
        # Assume pkt is of correct format
        domain = pkt[DNSQR].qname
        domain_parts = domain.split('.')[::-1]
        # Forward pkt, classified by first rule matched
        for rule in self.domains:
            # Split on period, then match last elements of split
            rule_parts = rule.split('.')[::-1]
            matched_parts = zip(rule_parts, domain_parts)
            match_equalities = (x==y for x,y in matched_parts)
            match = reduce(lambda x,y: x and y, match_equalities)
            if match:
                return classify_pkt(pkt, 'ILLEGAL_DOMAIN', rule=rule)
            return None

    def filter_by_signatures(self, pkt):
        #TODO get payload of pkt
        if match:
            #rule_escaped = rule.encode('string_escape')
            return classify_pkt(pkt, 'ILLEGAL_SIGNATURE', rule=rule)
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
