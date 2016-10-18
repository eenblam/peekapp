#!/usr/bin/env python2

import click
import logging
import scapy
import fileinput
from sys import stdin, stdout

@click.group()
@click.option('--signatures', '-s', type=click.File('rb'))
@click.option('--blacklists', '-b', type=click.File('rb'))
@click.argument('log', default='peekapp.log', type=click.File('wb'))
def cli(signatures, blacklists, log):
    """
    peekapp is a PCAP-monitoring IDS layer.
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
