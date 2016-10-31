from scapy.all import sniff
from peekapp.pipes import Sink
from fixtures.fixtures import signature_pipeline

def test_packet_signature_analysis(signature_pipeline):
    source, drain = signature_pipeline
    msgs = []
    sink_to_list = Sink(callback=msgs.append)
    drain > sink_to_list
    sniff(offline='tests/files/both.pcap',
            prn=source.push, timeout=0.5)

    with open('tests/files/signatures.cfg','r') as f:
        # Drop newline character (strip too dangerous here)
        signatures = [line[:-1].decode('string_escape') for line in f]

    has_sig = lambda p: True in (s in p for s in signatures)

    payloads = (msg.payload.decode('string_escape') for msg in msgs)
    msgs_contain_signature = (has_sig(p) for p in payloads)

    assert all(msgs_contain_signature)
    # 48 = 24 requests + 24 responses, as in README
    assert len(msgs) == 48
