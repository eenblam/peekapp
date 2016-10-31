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

@pytest.fixture
def url_pipeline():
    with open('tests/files/hack_url_rules.cfg','r') as url_rules:
        blacklist = Blacklist(URL_file=url_rules)

    source = Source()
    bad_urls = Pipe(transform=blacklist.filter_by_URL)
    source > bad_urls
    return source, bad_urls

@pytest.fixture
def signature_pipeline():
    with open('tests/files/signatures.cfg','r') as signatures:
        blacklist = Blacklist(signature_file=signatures)

    source = Source()
    bad_signatures = Pipe(transform=blacklist.filter_by_signatures)
    source > bad_signatures
    return source, bad_signatures
