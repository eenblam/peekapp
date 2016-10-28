#!/usr/bin/env python2

import click
from scapy.all import (SniffSource, RdpcapSource,
                    IP, UDP,
                    TransformDrain, PipeEngine,
                    in6_getifaddr)

from peekapp import filters
from peekapp.blacklist import Blacklist
from peekapp.pipes import *

@click.group(invoke_without_command=True)
@click.option('--domain-blacklist', '-d', type=click.File('r'),
        help='File listing domains for which any DNS traffic should trigger an alert')
@click.option('--url-blacklist', '-u', type=click.File('r'),
        help='File listing strings triggering an alert when present in URLs')
@click.option('--ip-blacklist', '-i', type=click.File('r'),
        help='File listing IPs for which any traffic should trigger an alert')
@click.option('--signatures', '-s', type=click.File('r'),
        help='File listing TCP/UDP payload signatures')
@click.option('--logfile', '-l', type=click.File('a'))
@click.pass_context
def cli(ctx, domain_blacklist, url_blacklist,
        ip_blacklist, signatures, logfile):
    """
    peekapp is a packet-monitoring IDS layer, which records traffic in logfile.
    """
    if not logfile:
        import sys
        click.echo('No logfile. See "peekapp -h" for options and arguments.')
        sys.exit(1)

    ctx.obj['blacklist'] = Blacklist(domain_file=domain_blacklist,
                            URL_file=url_blacklist,
                            IP_file=ip_blacklist,
                            signature_file=signatures)

    ctx.obj['logfile'] = logfile

@cli.command()
#@click.argument('packets', type=click.File('rb'))
@click.argument('packets', type=click.File('rb', lazy=True))
@click.pass_context
def pcap(ctx, packets):
    """
    Perform static analysis on a PCAP dump
    """
    #TODO RdpcapSource expects filename, not file handle...
    #  ...might want to rewrite the packets argument to just accept a string
    filename = packets.name
    sniffer = RdpcapSource(fname=filename, name='Sniffer')
    main(ctx=ctx, source=sniffer)

@cli.command()
@click.argument('interface', nargs=1)
@click.pass_context
def iface(ctx, interface):
    """
    Monitor a specific network interface
    """
    # See scapy.arch.linux.in6_getifaddr:
    # Returns a list of 3-tuples of the form (addr, scope, iface) where
    # 'addr' is the address of scope 'scope' associated to the interface
    # 'ifcace'.
    interfaces = [x[-1] for x in in6_getifaddr()]
    if interface not in interfaces:
        # No exception to catch!
        # SniffSource will fail silently if interface doesn't exist.
        import sys
        click.echo('Interface "{}" not found.'.format(interface))
        click.echo('Peekapp found the following:\n\t{}'
                .format('\n\t'.join(interfaces)))
        sys.exit(1)

    sniffer = SniffSource(iface=interface, name='Sniffer')
    main(ctx=ctx, source=sniffer)

def main(ctx, source):
    # Plumbing
    blacklist = ctx.obj['blacklist']

    escalator = EscalationDrain(name='Escalation of logs to Alert level')
    aggregator = AggregationDrain(name='Alert-level aggregator')
    alert_sink = AlertSink(name='Alert sink')
    log_sink = LogSink(logfile=ctx.obj['logfile'], name='Log sink')

    escalator > log_sink
    #escalator >> aggregator >> alert_sink

    #TODO DNS domain blacklists from config
    if blacklist.domains:
        dns_requests = FilterDrain(filter=filters.is_DNS_query,
                                name='UDP DNS Requests')
        dns_msgs = TransformDrain(f=blacklist.filter_by_domains,
                                name='UDP DNS packets')
        dns_bad = FilterDrain(filter=lambda x: x is not None,
                                name='Keep DNS packets for blacklisted domains')
        source > dns_requests > dns_msgs > dns_bad  > escalator

    if blacklist.IPs:
        ip_blacklist = FilterDrain()
        #source > ip_blacklist > escalator

    if blacklist.URLs:
        http_requests = FilterDrain()
        #bad_http = FilterDrain()
        #source > http_requests > bad_http > escalator

    if blacklist.signatures:
        payload_signatures = FilterDrain(filter=filters.has_transport_payload,
                                        name='Has transport layer payload')
        #bad_payload = FilterDrain()
        #source > payload_signatures > bad_payload > escalator

    #TODO All of port scan detection
    #port_scan_detector = PortScanDrain()
    #source > port_scan_detector > escalator


    #TODO DEBUG with logger
    try:
        engine = PipeEngine(source)
        engine.start()
    except KeyboardInterrupt:
        click.echo('\n\tPeekapp exiting on keyboard interrupt.')
        engine.stop()
 
if __name__ == '__main__':
    cli(obj={})
