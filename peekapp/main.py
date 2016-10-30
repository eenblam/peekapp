import click
from peekapp import loggify, filters
from peekapp.pipes import *
from peekapp.alerts import *

def main(blacklist, logfile):
    # Plumbing
    source = Source()
    fork = Pipe()
    log_formatter = Pipe(transform=lambda log: loggify(log) + '\n')
    log_sink = LogSink(logfile=logfile)
    alert_pool = PacketBuffer(timeout=0.5)
    alert_formatter = Pipe(transform=summarize_pretty)
    alert_sink = Sink(click.echo)

    fork > log_formatter > log_sink
    fork > alert_pool > alert_formatter > alert_sink

    # Establish pipelines
    if blacklist.domains:
        dns_requests = Pipe(filter=filters.is_DNS_query,
                transform=blacklist.filter_by_domains)
        dns_bad = Pipe(filter=lambda x: x is not None)
        source > dns_requests > dns_bad > fork

    if blacklist.IPs:
        ip_blacklist = Pipe()
        #source > ip_blacklist > fork

    if blacklist.URLs:
        http_requests = Pipe()
        #bad_http = Pipe()
        #source > http_requests > bad_http > fork

    if blacklist.signatures:
        payload_signatures = Pipe(filter=filters.has_transport_payload,
                transform=blacklist.filter_by_signatures)
        bad_payloads = Pipe(filter=lambda x: x is not None)
        source > payload_signatures > bad_payloads > fork

    #TODO All of port scan detection
    #port_scan_detector = PortScanBuffer()
    #source > port_scan_detector > fork

    return source


