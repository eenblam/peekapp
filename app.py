#!/usr/bin/env python2

import click
from scapy.all import sniff, IP, UDP

@click.group()
@click.option('--signatures', '-s', type=click.File('rb'),
        help='File listing TCP/UDP payload signatures')
@click.option('--blacklists', '-b', type=click.File('rb'),
        help='File listing strings triggering an alert when present in URls')
@click.option('--ip_blacklist', '-i', type=click.File('rb'),
        help='File listing IPs for which any traffic should trigger an alert')
@click.argument('log', default='peekapp.log', type=click.File('wb'))
def cli(signatures, blacklists, ip_blacklist, log):
    """
    peekapp is a PCAP-monitoring IDS layer, which records traffic in LOG.
    """
    pass

@cli.command()
@click.argument('packets', type=click.File('rb'))
def pcap(packets):
    """
    Perform static analysis on a PCAP dump
    """
    sniff(offline=packets)

@cli.command()
@click.argument('interface', nargs=1)
def iface(interface):
    """
    Monitor a specific network interface
    """
    sniff(iface=interface)

if __name__ == '__main__':
    cli()
