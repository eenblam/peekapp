#!/usr/bin/env python2

import click
from scapy.all import (sniff, in6_getifaddr)

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
@click.argument('packets', type=click.File('rb'))
@click.pass_context
def pcap(ctx, packets):
    """
    Perform static analysis on a PCAP dump
    """

    #filename = packets.name
    source = main(ctx)
    try:
        sniff(offline=packets, prn=source.push)
    except KeyboardInterrupt:
        click.echo('\n\tHalting on keyboard interrupt.')

@cli.command()
@click.argument('interface', nargs=1, type=str)
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

    source = main(blacklist=ctx.obj['blacklist'],
            logfile=ctx.obj['logfile'])
    try:
        # For some reason, click calls this function a second time...
        # ...but with interface as <type 'unicode'>...
        # ...which breaks struct.pack("16s16x", iff) in scapy/arch/common.py
        sniff(iface=str(interface), prn=source.push)
    except KeyboardInterrupt:
        click.echo('\n\tHalting on keyboard interrupt.')

def main(blacklist, logfile):
    # Plumbing
    source = Source()
    fork = Pipe()
    log_sink = LogSink(logfile=logfile)
    alert_buffer = AlertBuffer(cooldown=0.5)
    alert_sink = Sink(click.echo)

    fork > log_sink
    fork > alert_buffer > alert_sink

    # Establish pipelines
    if blacklist.domains:
        dns_requests = Pipe(filter=filters.is_DNS_query,
                transform=blacklist.filter_by_domains)
        dns_bad = Pipe(filter=lambda x: x is not None)
        source > dns_requests > dns_bad > fork

    if blacklist.IPs:
        ip_blacklist = Pipe()
        #source > ip_blacklist > escalator

    if blacklist.URLs:
        http_requests = Pipe()
        #bad_http = Pipe()
        #source > http_requests > bad_http > escalator

    if blacklist.signatures:
        payload_signatures = Pipe(filter=filters.has_transport_payload)
        #bad_payload = Pipe()
        #source > payload_signatures > bad_payload > escalator

    #TODO All of port scan detection
    #port_scan_detector = PortScanBuffer()
    #source > port_scan_detector > escalator

    return source

if __name__ == '__main__':
    cli(obj={})
