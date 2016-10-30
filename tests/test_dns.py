from scapy.all import sniff
from peekapp.pipes import Sink
from fixtures.fixtures import dns_pipeline

# Test: Pipeline outputs expected packets and *only* expected packets
# - Test number (48 QR, 24 not RR icanhazip.com., 316 docs.pytest.org.)
# - Test domains (only icanhazip.com.)
# - TODO: Test that domain.ext and sub.domain.ext are matched
def test_dns_queries(dns_pipeline):
    source, drain = dns_pipeline
    pkt_list = []
    sink_to_list = Sink(callback=pkt_list.append)
    drain > sink_to_list
    msgs = sniff(offline='tests/files/icanhazip_or_pytest.pcap',
            prn=source.push, timeout=0.5)

    assert len(pkt_list) == 24
    last_two = (msg.payload.split('.')[-2:]
            for msg in pkt_list)
    joined = ('.'.join(pair) for pair in last_two)
    domains_are_correct = (domain == 'icanhazip.com' for domain in joined)
    assert all(domains_are_correct)
