# peekapp/__init__.py

import click

from peekapp.alerts import *
from peekapp.blacklist import *
from peekapp.util import *
from peekapp.filters import *
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
@click.option('--logfile', '-l', type=click.File('a'),
        help='Output file to which logged packets are appended')
@click.pass_context
def cli(ctx, domain_blacklist, url_blacklist,
        ip_blacklist, signatures, logfile):
    """
    peekapp is a packet-monitoring IDS layer.
    """
    if not logfile:
        import sys
        click.echo('No logfile. See "peekapp --help" for options and arguments.')
        sys.exit(1)

    ctx.obj['blacklist'] = Blacklist(domain_file=domain_blacklist,
                            URL_file=url_blacklist,
                            IP_file=ip_blacklist,
                            signature_file=signatures)

    ctx.obj['logfile'] = logfile

from peekapp.interface import *

def run():
    cli(obj={})
