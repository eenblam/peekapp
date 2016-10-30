# classifiers.py

# Message formatters / classifiers
from scapy.all import NoPayload, IP
from collections import namedtuple
#TODO Add 'rule' field to MSG to identify what was matched on
MSG = namedtuple('msg', ['timestamp', 'src', 'dst', 'traffic_type',
                         'rule', 'payload', 'pkt'])

def classify_pkt(pkt, traffic_type, payload, rule=None):
    msg = MSG(timestamp=pkt.time,
            src=pkt[IP].src,
            dst=pkt[IP].dst,
            traffic_type=traffic_type,
            rule=rule,
            payload=payload,
            pkt=pkt)
    return msg

def loggify(msg):
    always_use = [msg.traffic_type, msg.timestamp, msg.src, msg.dst, msg.rule]
    log = ' '.join(str(field) for field in always_use)
    if type(msg.payload) is NoPayload or msg.payload is NoPayload():
        return log.encode('string_escape') + ' NoPayload'
    return (log + ' ' + str(msg.payload)).encode('string_escape')
