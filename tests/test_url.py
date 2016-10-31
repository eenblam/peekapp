from scapy.all import sniff
from peekapp.pipes import Sink
from fixtures.fixtures import url_pipeline

def test_url_contents(url_pipeline):
    source, drain = url_pipeline
    msgs = []
    sink_to_list = Sink(callback=msgs.append)
    drain > sink_to_list
    sniff(offline='tests/files/hack.pcap',
            prn=source.push, timeout=0.5)

    msgs_contain_target = ('hack' in msg.payload for msg in msgs)
    assert all(msgs_contain_target)
    assert len(msgs) == 6
