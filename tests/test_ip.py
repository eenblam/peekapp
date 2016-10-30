from scapy.all import sniff
from peekapp.pipes import Sink
from fixtures.fixtures import ip_pipeline

def test_exactly_and_only_given_ips(ip_pipeline):
    source, drain = ip_pipeline
    msgs = []
    sink_to_list = Sink(callback=msgs.append)
    drain > sink_to_list
    sniff(offline='tests/files/hack.pcap',
            prn=source.push, timeout=0.5)

    with open('tests/files/hack_ips.cfg','r') as f:
        ips = [line.strip() for line in f]

    check = lambda msg: msg.src in ips or msg.dst in ips
    msgs_match_an_ip = [check(msg) for msg in msgs]
    assert all(msgs_match_an_ip)
    assert len(msgs) == 169
