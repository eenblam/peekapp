# peekapp/pipes.py

from collections import defaultdict
import time
from scapy.pipetool import _ConnectorLogic
from scapy.all import NoPayload

# I need to reimplement pipetool, but without threading or source tracking
# The former keeps blowing up in Scapy, and the latter isn't needed here
class Source(_ConnectorLogic):
    def __init__(self):
        _ConnectorLogic.__init__(self)

    def push(self, msg):
        for s in self.sinks:
            s.push(msg)

class Pipe(_ConnectorLogic):
    def __init__(self, filter=None, transform=None, push_none=False):
        _ConnectorLogic.__init__(self)
        self.filter = filter if filter is not None else lambda _: True
        self.transform = transform
        self._push_none = push_none

    def push(self, msg):
        if self.filter(msg):
            out = self.transform(msg) if self.transform is not None else msg

            if not self._push_none and out is None:
                return

            for s in self.sinks:
                s.push(out)

class Sink(_ConnectorLogic):
    def __init__(self, callback):
        _ConnectorLogic.__init__(self)
        self._callback = callback

    def push(self, msg):
        self._callback(msg)

class LogSink(_ConnectorLogic):
    def __init__(self, logfile=None):
        """Writes msg to specified log file on push

        :param log_file: handle to open log file
        """
        _ConnectorLogic.__init__(self)
        self.logfile = logfile

    def push(self, msg):
        self.logfile.write(msg)

class PortScanBuffer(Pipe):
    """Aggregates low messages (groupby) to track repeated SYN packets.
    Watch for single source to send SYN packets to multiple ports
    in less than <tolerance> time.
    Once timeout has expired, send a summary message regarding accumulated packets.
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
