import pytest
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
