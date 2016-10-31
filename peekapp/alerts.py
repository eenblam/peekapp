# peekapp/alerts.py

from peekapp.pipes import *

class AlertBuffer(object):
    """Probably not what you want. See PacketBuffer."""
    def __init__(self, msg, timeout=300):
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
        """Creates a new PacketBuffer

        :param timeout: number of minutes redundant packets are held
        :type timeout: int or float
        """

        Pipe.__init__(self)
        self.timeout = timeout * 60
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
