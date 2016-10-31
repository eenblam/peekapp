# peekapp/alerts.py

from peekapp.pipes import *

class AlertCache(object):
    """Probably not what you want. See PacketBuffer."""
    def __init__(self, msg, timeout=300):
        self.previous = msg

        self.timeout = timeout
        self.items = []

    def __len__(self):
        return len(self.items)

    def append(self, msg):
        """Add a msg to the end of the buffer"""
        self.items.append(msg)

    def expired(self):
        """Determine if buffer has exceeded its timeout
        
        Note that the buffer needs to timeout past the timestamp of previous,
        not the smallest timestamp!
        """
        return self.timeout < (time.time() - self.previous.timestamp)

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

    def _send(self, msg):
        for s in self.sinks:
            s.push(msg)

    def flushables(self):
        return ((key, pktcache) for key, pktcache in self.cache.items()
                if pktcache.expired())

    def flush(self):
        """Send and drop cached packets beyond timeout"""
        for key, pktcache in self.flushables():
            if len(pktcache):
                # Send only if nonempty
                self._send({'msgs': pktcache.items,
                            'previous': pktcache.previous})

            del self.cache[key]

    def push(self, msg):
        # Add to cache, alert if new, then flush
        key = (msg.src, msg.dst, msg.traffic_type)

        if key not in self.cache.keys():
            self.cache[key] = AlertCache(msg=msg, timeout=self.timeout)
            self._send({'msgs':[msg], 'previous': None})
        else:
            self.cache[key].append(msg)

        self.flush()
