import pytest
from peekapp.blacklist import Blacklist
from peekapp.pipes import Source, Pipe, Sink
from peekapp import filters

@pytest.fixture
def dns_pipeline():
    with open('tests/files/icanhazip.cfg','r') as domains:
        blacklist = Blacklist(domain_file=domains)

    source = Source()
    bad_dns = Pipe(filter=filters.is_DNS_query,
            transform = blacklist.filter_by_domains)
    source > bad_dns
    return source, bad_dns

@pytest.fixture
def ip_pipeline():
    with open('tests/files/hack_ips.cfg','r') as ips:
        blacklist = Blacklist(IP_file=ips)

    source = Source()
    bad_ips = Pipe(transform=blacklist.filter_by_IP)
    source > bad_ips
    return source, bad_ips
