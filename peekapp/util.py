# peekapp/util.py

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
    if not validate_payload(msg.payload):
        return log + ' NoPayload'
    return log + ' ' + str(msg.payload)

# Alert summarizers

def summarize_pretty(buffered_pkts):
    """Pretty output for humans, not for analysis"""
    msgs = buffered_pkts['msgs']
    previous = buffered_pkts['previous']
    count = len(msgs)
    if not previous:
        p = msgs[0]
    else:
        p = previous

    # Pro NLP right here
    plurality = 's' if count > 1 else ''

    what = '{} {} packet{} from {} to {}'.format(
                p.traffic_type, count, plurality,
                p.src, p.dst)

    if previous:
        when = ' between {} and {}'.format(p.timestamp,
                max(msg.timestamp for msg in msgs))
    else:
        when = ' at {}'.format(p.timestamp)

    payloads = (msg.payload for msg in msgs
            if validate_payload(msg.payload))

    if payloads:
        return what + when + '\n\t' + '\n\t'.join(payloads)
    return what + when


def validate_payload(payload):
    return (type(payload) is not NoPayload
            and payload is not NoPayload())
