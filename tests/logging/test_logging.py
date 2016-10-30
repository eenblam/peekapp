import pytest
from scapy.all import sniff
from peekapp.blacklist import Blacklist
from peekapp.pipes import Source, Pipe, Sink
from peekapp import filters

@pytest.fixture
def dns_pipeline():
    with open('tests/files/icanhazip.cfg','r') as domains:
        blacklist = Blacklist(domain_file=domains)

    source = Source()
    dns_requests = Pipe(filter=filters.is_DNS_query,
            transform = blacklist.filter_by_domains)
    dns_bad = Pipe(filter=lambda x: x is not None)
    source > dns_requests > dns_bad
    return source, dns_bad

#TODO: Fixture: Get open handle to tmp logfile

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

    print len(pkt_list)
    assert len(pkt_list) == 24
    last_two = (msg.payload.split('.')[-2:]
            for msg in pkt_list)
    joined = ('.'.join(pair) for pair in last_two)
    domains_are_correct = (domain == 'icanhazip.com' for domain in joined)
    assert all(domains_are_correct)

# TODO: Test: Log format is as expected
