# classifiers.py

# Message formatters / classifiers
from scapy.all import NoPayload
from collections import namedtuple
#TODO Add 'rule' field to MSG to identify what was matched on
MSG = namedtuple('msg', ['timestamp', 'src', 'dst', 'traffic_type',
                         'rule', 'payload', 'pkt'])

def classify_pkt(pkt, traffic_type, rule=None, payload=NoPayload):
    msg = MSG(timestamp=pkt.time,
            src=pkt[IP].src,
            dst=pkt[IP].dst,
            traffic_type=traffic_type,
            rule=rule,
            payload=payload,
            pkt=pkt)
    return msg
