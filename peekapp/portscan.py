# peekapp/portscan.py

from peekapp import Pipe, MSG
from peekapp.util import classify_pkt

def filter_by_TCP_syn(pkt):
    flags = pkt.sprintf('%TCP.flags%')
    if 'S' in flags:
        return classify_pkt(pkt, 'PORT_SCAN',
                payload=None)

def aggregate_pscache(pscache):
    """Aggregates MSGs in pscache into single MSG
    """
    # src, dst, traffic type all the same
    # Get min and max timestamps
    #
    # Payload: range of ports scanned
    # ...or list of ports if count is sufficiently small
    first = pscache[0]
    length = len(pscache)
    timespan = first.timestamp - pscache[-1].timestamp

    rule = '{}Messages{}Seconds'.format(length, timespan)

    dports = (msg.pkt.dport for msg in pscache.items)
    payload = ','.join(dports)

    return MSG(timestamp=first.timestamp,
            src=first.src,
            dst=first.dst,
            traffic_type=first.traffic_type,
            rule=rule,
            payload=payload,
            pkt=pkt)

class PSCache(object):
    """TODO

    Assumes inputs are given in nondecreasing order
    """
    def __init__(self, msg, timeout, tolerance):
        self.items = [msg]
        self.timeout = timeout

    def __len__(self):
        return len(self.items)

    def append(self, msg):
        t = msg.timestamp
        last_t = self.items[-1].timestamp

        if t < last_t:
            raise ValueError('received timestamps in nondecreasing order: '
                    '{}, {}'.format(last_t, t))

        # Existing window didn't work, so trim old msgs
        items = [item for item in self.items
                if self.timeout > t - item.timestamp]
        self.items = items + [msg]

class PSBuffer(Pipe):
    def __init__(self, timeout=0.5, tolerance=20):
        """Forwards packet cache if tolerance SYNs occur in timeout seconds

        :param timeout: number of seconds in detection window
        :type timeout: int or float
        :param tolerance: number SYNs from one source needed to trigger
        :type tolerance: int
        """
        Pipe.__init__(self)
        self.timeout = timeout
        self.tolerance = tolerance
        self.cache = {}

    def _send(self, msg):
        for s in self.sinks:
            s.push(msg)

    def flushables(self):
        return ((key, pscache) for key, pscache in self.cache.items()
                if len(pscache) >= self.tolerance)

    def flush(self):
        """Send and drop cache SYN packets beyond timeout"""
        for key, pscache in self.flushables():
            self._send(pscache)

            del self.cache[key]

    def push(self, msg):
        key = (msg.src, msg.dst)
        try:
            self.cache[key].append(msg)
        except ValueError:
            # Likely that timestamp is off
            continue
        except KeyError:
            self.cache[key] = PSCache(msg=msg,
                    timeout=self.timeout,
                    tolerance=self.tolerance)

        self.flush()
