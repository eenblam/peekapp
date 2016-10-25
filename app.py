#!/usr/bin/env python2

import click
from scapy.all import (SniffSource, RdpcapSource,
                    IP, UDP,
                    PipeEngine)
import filters
import pipes

@click.group()
@click.option('--signatures', '-s', type=click.File('rb'),
        help='File listing TCP/UDP payload signatures')
@click.option('--blacklists', '-b', type=click.File('rb'),
        help='File listing strings triggering an alert when present in URLs')
@click.option('--ip_blacklist', '-i', type=click.File('rb'),
        help='File listing IPs for which any traffic should trigger an alert')
@click.argument('logfile', default='peekapp.log', type=click.File('wb'))
def cli(signatures, blacklists, ip_blacklist, log):
    """
    peekapp is a packet-monitoring IDS layer, which records traffic in logfile.
    """
    pass

@cli.command()
@click.argument('packets', type=click.File('rb'))
def pcap(packets):
    """
    Perform static analysis on a PCAP dump
    """
    sniffer = RdpcapSource(fname=packets, name='Sniffer')
    main(sniffer)

@cli.command()
@click.argument('interface', nargs=1)
def iface(interface):
    """
    Monitor a specific network interface
    """
    sniffer = SniffSource(iface=interface, name='Sniffer')
    main(sniffer)

def main(sniffer):
    # Plumbing
    #TODO IP blacklist from config
    ip_blacklist = FilterDrain()

    #TODO DNS domain blacklists from config
    dns_requests = FilterDrain(filter=is_DNS_query,
                            name='UDP DNS Requests')
    bad_dns = FilterDrain()

    #TODO HTTP blacklist strings from config
    http_requests = FilterDrain()
    bad_http = FilterDrain()

    #TODO Payload signatures from config
    payload_signatures = FilterDrain(filter=has_transport_payload,
                                    name='Has transport layer payload')
    bad_payload = FilterDrain()

    #TODO All of port scan detection
    port_scan_detector = PortScanDrain()

    escalator = EscalationDrain(name='Escalation of logs to Alert level')
    aggregator = AggregationDrain(name='Alert-level aggregator')

    log_sink = LogSink(logfile=log, name='Log sink')
    alert_sink = AlertSink(name='Alert sink')

    # Most of the architecture is just a DAG of acceptor automata
    # ...but I'm not so hardcore that I'm bothering with scapy.automata
    sniffer > ip_blacklist > escalator
    sniffer > dns_requests > bad_dns > escalator
    sniffer > http_requests > bad_http > escalator
    sniffer > payload_signatures > bad_payload > escalator
    sniffer > port_scan_detector > escalator
    escalator > log_sink
    escalator >> aggregator >> alert_sink

    try:
        engine = PipeEngine(sniffer)
        engine.start()
    except KeyboardInterrupt:
        engine.stop()
 
if __name__ == '__main__':
    cli()
