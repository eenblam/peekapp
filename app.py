#!/usr/bin/env python2

import click
import logging
import scapy
import fileinput
from sys import stdin, stdout

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
    Monitor a PCAP format packet dump
    """
    pass

@cli.command()
@click.argument('interface', nargs=1)
def iface(interface):
    """
    Monitor a specific network interface in promiscuous mode
    """
    pass

if __name__ == '__main__':
    cli()
