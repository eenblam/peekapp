from peekapp.pipes import *

class AlertBuffer(object):
    """Probably not what you want. See PacketBuffer."""
    def __init__(self, msg, timeout=5):
        self.previous = msg

        self.timeout = timeout
        self.records = []

    def __len__(self):
        return len(self.records)

    def append(self, msg):
        """Add a msg to the end of the buffer"""
        self.records.append(msg)

    def expired(self):
        """Determine if buffer has exceeded its timeout"""
        return self.timeout < (time.time() - self.previous.timestamp)

    def latest(self):
        """Time of latest record added, or previous record when buffer empty"""
        if self.records:
            return max(msg.timestamp for msg in self.records)
        return self.previous.timestamp

class PacketBuffer(Pipe):
    """Performs groupby and reduce on msgs and sends reduction after timeout"""
    def __init__(self, timeout=5):
        Pipe.__init__(self)
        self.timeout = timeout * 60 #TODO Document arguments. Expect minutes.
        self.cache = {}

    def flushables(self):
        return ((key, pktbuf) for key, pktbuf in self.cache.items()
                if pktbuf.expired())

    def flush(self):
        """Send and drop cached packets beyond timeout"""
        for key, pktbuf in self.flushables():
            if len(pktbuf):
                # Send only if nonempty
                self._send({'msgs': pktbuf.records,
                            'previous': pktbuf.previous})

            del self.cache[key]

    def _send(self, msg):
        for s in self.sinks:
            s.push(msg)

    def push(self, msg):
        # Add to cache, alert if new, then flush
        key = (msg.src, msg.dst, msg.traffic_type)

        if key not in self.cache.keys():
            self.cache[key] = AlertBuffer(msg=msg, timeout=self.timeout)
            self._send({'msgs':[msg], 'previous': None})
        else:
            self.cache[key].append(msg)

        self.flush()

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
                if type(msg.payload) is not NoPayload
                and msg.payload is not NoPayload())

    if payloads:
        return what + when + '\n\t' + '\n\t'.join(payloads)
    return what + when
