from scapy.all import (Drain, Sink, NoPayload)
from collections import defaultdict
import time

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
        self.cooldown = cooldown * 60 #TODO Document arguments. Expect minutes.
        self.cache = defaultdict(list)

    def cache_summary(self, key):
        '''TODO'''
        src, dst, traffic_type = key
        records = self.cache[key]
        #TODO Convert timestamps to datetime
        min_time = records[0].timestamp
        max_time = records[-1].timestamp
        count = len(records)
        #TODO Pass min and max times with records for logging elapsed time

        # Top-notch NLP here
        plurality = 's' if len(records) > 1 else ''
        alert = '[{}] {} packet{} between {} and {}'.format(traffic_type,
                    pkt_count, plurality, min_time, max_time)
        payloads = [record.payload for record in records
                    if type(payload) is not NoPayload]
        # "if payload" *might* be faster, but this is more explicit

        payload_dump = '\n\t' + '\n\t'.join(payloads) if payloads else ''

        return alert + payload_dump

    def record_expired(self, timestamp):
        '''Determine if timestamp's cooldown has expired'''
        return self.cooldown < time.time() - timestamp

    def flush(self):
        '''Summarize, send, and drop cached packets beyond cooldown'''
        flushables = (key for key, records in self.cache.items()
                        if self.record_expired(records[0].timestamp))

        for key in flushables:
            #TODO Should I expect a KeyError?
            # I'm most worried about exceptions from _high_send...
            # (don't want to delete cache entry without sending)

            out = self.cache_summary(key)
            self._high_send(out)
            del self.cache[key]

    def high_push(self, msg):
        key = (msg.src, msg.dst, msg.traffic_type)

        if key not in self.cache.keys():
            self._high_send(msg)

        self.cache[key].append(msg)

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
        #TODO Convert timestamp to datetime
        if type(msg.payload) is NoPayload:
            log = ' '.join(msg[:-2])
        else:
            log = ' '.join(msg[:-1])

        self.logfile.write(log.encode('string_escape'))

class AlertSink(Sink):
    '''Formats alerts and writes them to stdout'''
    def __init__(self, name=None):
        Sink.__init__(self, name=name)

    def high_push(self,msg):
        # Groupby and caching handled previously
        # Just handles formatting and writing to terminal
        pass

