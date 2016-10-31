import click
from peekapp import loggify, filters, summarize_pretty
from peekapp.pipes import *
from peekapp.alerts import *

def main(blacklist, logfile, alert_timeout):
    # Plumbing
    source = Source()
    fork = Pipe()
    log_formatter = Pipe(transform=lambda log: loggify(log) + '\n')
    log_sink = LogSink(logfile=logfile)
    alert_pool = PacketBuffer(timeout=alert_timeout)
    alert_formatter = Pipe(transform=summarize_pretty)
    alert_sink = Sink(click.echo)

    fork > log_formatter > log_sink
    fork > alert_pool > alert_formatter > alert_sink

    # Establish pipelines
    if blacklist.domains:
        bad_dns = Pipe(filter=filters.is_DNS_query,
                transform=blacklist.filter_by_domains)
        source > bad_dns > fork

    if blacklist.IPs:
        bad_ips = Pipe(transform=blacklist.filter_by_ip)
        source > bad_ips > fork

    if blacklist.URLs:
        bad_http_payload = Pipe(transform=blacklist.filter_by_URL)
        source > bad_http_payload > fork

    if blacklist.signatures:
        #bad_payload_signatures = Pipe(filter=filters.has_transport_payload,
        #        transform=blacklist.filter_by_signatures)
        bad_payload_signatures = Pipe(transform=blacklist.filter_by_signatures)
        source > bad_payload_signatures > fork

    #TODO All of port scan detection
    #port_scan_detector = PortScanBuffer()
    #source > port_scan_detector > fork

    return source


