# peekapp/filters.py
from scapy.all import DNSQR

def with_layers(*layers):
    """Accept packet if it has any of the listed layers"""
    def pkt_has_layers(pkt):
        return True in (pkt.haslayer(layer) for layer in layers)
    return pkt_has_layers

def without_layers(*layers):
    def pkt_lacks_layers(pkt):
        return True not in (pkt.haslayer(layer) for layer in layers)
    return pkt_lacks_layers

def with_sources(*sources):
    """Keep only packets from listed sources"""
    #TODO Try to get pkt[2].src; bail if IndexError
    pass

def with_destinations(*destinations):
    """Keep only packets bound for one of the listed destinations"""
    #TODO Try to get pkt[2].dst; bail if IndexError
    pass

def with_signatures(*signatures):
    """Keep only packets identifiable with specific signatures"""
    pass

def is_DNS_query(pkt):
    return pkt.haslayer(DNSQR)

def has_transport_payload(pkt):
    #TODO Check not isinstance(pkt[2].payload, scapy.packet.NoPayload)
    try:
        return not isinstance(pkt[2].payload, scapy.packet.NoPayload)
    except IndexError:
        # No transport layer!
        return False
