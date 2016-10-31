# peekapp/interface.py

import click
from scapy.all import (sniff, in6_getifaddr)

from peekapp import cli
from peekapp.main import main

@cli.command()
@click.argument('packets', type=click.File('r'))
@click.pass_context
def pcap(ctx, packets):
    """
    Perform static analysis on a PCAP dump
    """
    source = main(blacklist=ctx.obj['blacklist'],
            logfile=ctx.obj['logfile'])
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
