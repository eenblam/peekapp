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
        bad_dns_or_none = Pipe(filter=filters.is_DNS_query,
                transform=blacklist.filter_by_domains)
        bad_dns = Pipe(filter=lambda x: x is not None)
        source > bad_dns_or_none > bad_dns > fork

    if blacklist.IPs:
        bad_ip_or_none = Pipe(transform=blacklist.filter_by_ip)
        bad_ips = Pipe(filter=lambda x: x is not None)
        source > bad_ip_or_none > bad_ips > fork

    if blacklist.URLs:
        bad_http_payload_or_none = Pipe()
        bad_http = Pipe(lambda x: x is not None)
        #source > bad_http_payload_or_none > bad_http > fork

    if blacklist.signatures:
        bad_signature_or_none = Pipe(filter=filters.has_transport_payload,
                transform=blacklist.filter_by_signatures)
        bad_payload_signatures = Pipe(filter=lambda x: x is not None)
        source > bad_signature_or_none > bad_payload_signatures > fork

    #TODO All of port scan detection
    #port_scan_detector = PortScanBuffer()
    #source > port_scan_detector > fork

    return source


