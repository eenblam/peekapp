from collections import defaultdict
import time
from scapy.pipetool import _ConnectorLogic
from scapy.all import NoPayload
from peekapp.classifiers import loggify_msg

# I need to reimplement pipetool, but without threading or source tracking
# The former keeps blowing up in Scapy, and the latter isn't needed here
class Source(_ConnectorLogic):
    def __init__(self):
        _ConnectorLogic.__init__(self)

    def push(self, msg):
        for s in self.sinks:
            s.push(msg)

class Pipe(_ConnectorLogic):
    def __init__(self, filter=None, transform=None):
        _ConnectorLogic.__init__(self)
        self.filter = filter if filter is not None else lambda _: True
        self.transform = transform

    def push(self, msg):
        if self.filter(msg):
            out = self.transform(msg) if self.transform is not None else msg
            for s in self.sinks:
                s.push(out)

class Sink(_ConnectorLogic):
    def __init__(self, callback):
        _ConnectorLogic.__init__(self)
        self._callback = callback

    def push(self, msg):
        self._callback(msg)

class LogSink(_ConnectorLogic):
    """Formats messages and writes them to specified log file

    ::log_file:: handle to open log file
    """
    def __init__(self, logfile=None):
        _ConnectorLogic.__init__(self)
        self.logfile = logfile

    def push(self, msg):
        #TODO Convert timestamp to datetime
        #if type(msg.payload) is NoPayload:
        #    log = ' '.join(str(x) for x in msg[:-2])
        #else:
        #    log = ' '.join(str(x) for x in msg[:-1])

        #self.logfile.write(log.encode('string_escape') + '\n')
        self.logfile.write(loggify_msg(msg))

class AlertBuffer(Pipe):
    """Performs groupby and reduce on msgs and sends reduction after cooldown"""
    def __init__(self, cooldown=5):
        Pipe.__init__(self)
        self.cooldown = cooldown * 60 #TODO Document arguments. Expect minutes.
        self.cache = defaultdict(list)

    def cache_summary(self, key):
        """TODO"""
        #TODO Need to skip first element of cache, since it's only cached for its timestamp!
        src, dst, traffic_type = key
        old_records = self.cache[key]
        #TODO Convert timestamps to datetime
        min_time = old_records[0].timestamp
        max_time = old_records[-1].timestamp
        # Drop original packet; cached only for timestamp
        records = old_records[1:]
        pkt_count = len(records)

        if not count:
            # Cache cooldown exceeded with no new records
            return

        #TODO Pass min and max times with records for logging elapsed time

        # Top-notch NLP here
        plurality = 's' if len(records) > 1 else ''
        alert = '[{}] {} packet{} between {} and {}'.format(
                    traffic_type, pkt_count, plurality, min_time, max_time)
        payloads = [record.payload for record in records
                    if type(payload) is not NoPayload]
        # "if payload" *might* be faster, but this is more explicit

        payload_dump = '\n\t' + '\n\t'.join(payloads) if payloads else ''
        return alert + payload_dump

    def record_expired(self, timestamp):
        """Determine if timestamp's cooldown has expired"""
        return self.cooldown < time.time() - timestamp

    def flush(self):
        """Summarize, send, and drop cached packets beyond cooldown"""
        flushables = (key for key, records in self.cache.items()
                        if self.record_expired(records[0].timestamp))

        for key in flushables:
            #TODO Should I expect a KeyError?
            # I'm most worried about exceptions from _high_send...
            # (don't want to delete cache entry without sending)

            out = self.cache_summary(key)
            if out:
                # Out is a nonempty string
                self.send(out)

            del self.cache[key]

    def push(self, msg):
        key = (msg.src, msg.dst, msg.traffic_type)

        if key not in self.cache.keys():
            for s in self.sinks:
                s.push(msg)

        self.cache[key].append(msg)

        #NOTE: The cache is only polled on receipt of a new packet...
        # ...not when a particular source's cooldown has expired.
        self.flush()

class PortScanBuffer(Pipe):
    """Aggregates low messages (groupby) to track repeated SYN packets.
    Watch for single source to send SYN packets to multiple ports
    in less than TOLERANCE time.
    Once COOLDOWN has expired, send a summary message regarding accumulated packets.
    - Initial timestamp
    - Src, Dest
    - Port range scanned (Just (min,max); don't worry if stuff is missing in between)
    - Number of scans aggregated
    """
    def __init__(self):
        Pipe.__init__(self)

    def push(self, msg):
        # TODO
        pass
