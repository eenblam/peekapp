from scapy.all import (Drain, Sink)

def FilterDrain(Drain):
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

def EscalationDrain(Drain):
    '''Fork low pushes to push at both levels'''
    def __init__(self, name=None):
        Drain.__init__(self, name=name)

    def push(self, msg):
        self._send(msg)
        self._high_send(msg)

def AggregationDrain(Drain):
    '''Performs groupby and reduce on msgs and sends reduction after cooldown'''
    def __init__(self, name=None):
        Drain.__init__(self, name=name)

    def high_push(self, msg):
        # aggregate, maybe alert
        # Wes suggests polling only on new packet.
        # I guess I can start there and file an issue
        # for implementing proper polling to dump cache after N minutes.
        pass

def PortScanDrain(Drain):
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

def LogSink(Sink):
    '''Formats messages and writes them to specified log file'''
    def __init__(self, logfile=None, name=None):
        Sink.__init__(self, name=name)
        self.logfile = logfile

    def push(self, msg):
        # Clean up message
        # Write to log file specified at runtime
        pass

def AlertSink(Sink):
    '''Formats alerts and writes them to stdout'''
    def __init__(self, name=None):
        Sink.__init__(self, name=name)

    def high_push(self,msg):
        # Groupby and caching handled previously
        # Just handles formatting and writing to terminal
        pass

