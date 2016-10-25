from scapy.all import (Drain, Sink, NoPayload)

# Message formatters / classifiers
from collections import namedtuple
#TODO Add 'rule' field to MSG to identify what was matched on
MSG = namedtuple('msg', ['timestamp', 'src', 'dst', 'type',
                         'payload', 'pkt'])

def classify_pkt(pkt, traffic_type, rule=None, payload):
    msg = MSG(time=pkt.time,
            src=pkt[IP].src,
            dst=pkt[IP].dst,
            type=traffic_type,
            rule=rule,
            payload=payload,
            pkt=pkt)
    return msg

# Drains
class FilterDrain(Drain):
    '''Drop packets that fail filter'''
    def __init__(self, filter, name=None):
        Drain.__init__(self, name=name)
        self.filter = filter

    def push(self, msg):
        if self.filter(msg):
            self._send(msg)

    def high_push(self, msg):
        if self.filter(msg):
            self._high_send(msg)

class EscalationDrain(Drain):
    '''Fork low pushes to push at both levels'''
    def __init__(self, name=None):
        Drain.__init__(self, name=name)

    def push(self, msg):
        self._send(msg)
        self._high_send(msg)

class AggregationDrain(Drain):
    '''Performs groupby and reduce on msgs and sends reduction after cooldown'''
    def __init__(self, name=None, cooldown=5):
        Drain.__init__(self, name=name)
        self.cooldown = cooldown

        self.cache = {}

    def cache(self, pkt):
        '''Format pkt and add to internal cache'''
        pass

    def cache_summary(self, key):
        '''asdf'''
        records = self.cache[key]
        min_time = records[0]['timestamp']
        max_time = records[-1]['timestamp']
        pass

    def record_expired(self, timestamp):
        '''Determine if timestamp's cooldown has expired'''
        #TODO Fiddle with datetime.datetime.now, self.cooldown, and timestamp
        pass

    def flush(self):
        '''Summarize, send, and drop cached packets beyond cooldown'''
        # Get (key, msg) for flushables
        #TODO Clean up cooldown check as records are implemented
        flushables = ((key, records) for key, records in self.cache.items()
                        if self.record_expired(records[0]['timestamp']))

        flushables = (key for key, records in self.cache.items()
                        if self.record_expired(records[0]['timestamp']))
        for key in flushables:
            try:
                out = self.cache_summary(key)
                self._high_send(out)
                del self.cache[key]
            except ???:
                # Uhhh...
                continue

    def high_push(self, msg):
        src = msg.src
        dst = msg.dst
        msg_type = msg.type
        key = (src, dst, msg_type)

        if key not in self.cache.keys():
            self._high_send(msg)

        self.cache(msg)

        #NOTE: The cache is only polled on receipt of a new packet...
        # ...not when a particular source's cooldown has expired.
        self.flush()

class PortScanDrain(Drain):
    '''Aggregates low messages (groupby) to track repeated SYN packets.
    Watch for single source to send SYN packets to multiple ports
    in less than TOLERANCE time.
    Once COOLDOWN has expired, send a summary message regarding accumulated packets.
    - Initial timestamp
    - Src, Dest
    - Port range scanned (Just (min,max); don't worry if stuff is missing in between)
    - Number of scans aggregated
    '''
    def __init__(self, name=None):
        Drain.__init__(self, name=name)

    def push(self, msg):
        # TODO
        pass

class LogSink(Sink):
    '''Formats messages and writes them to specified log file'''
    def __init__(self, logfile=None, name=None):
        Sink.__init__(self, name=name)
        self.logfile = logfile

    def push(self, msg):
        # Clean up message
        try:
            # Get necessary fields from message
            # timestamp, direction, src, dst, type, payload
            # Format to output string
            out = ''
        except KeyError: # AttributeError?
            # Uh-oh! Message wasn't formed correctly.
            # Write event to app log.
            pass
        # Write to log file specified at runtime
        with open(logfile, 'a') as f:
            f.write(out)

class AlertSink(Sink):
    '''Formats alerts and writes them to stdout'''
    def __init__(self, name=None):
        Sink.__init__(self, name=name)

    def high_push(self,msg):
        # Groupby and caching handled previously
        # Just handles formatting and writing to terminal
        pass

