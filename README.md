# peekapp
peekapp is a packet-monitoring IDS layer.

## Overview
### Features
As specified in the project requirements,
peekapp will detect, log, and alert on:

- [x] Any traffic to or from blacklisted IP addresses
- [x] DNS requests for blacklisted domain names
- [x] Unencrypted web traffic to URLs containing a set of blacklisted strings 
- [x] TCP or UDP payloads containing any of a set of simple signatures
- [ ] Network port scanning activity

TODO Describe extensibility
(writing custom log formatters, alert summarizers, etc.)

### Installation and Basic Usage
Peekapp requires Python 2.7,
and the use of a virtual environment is highly recommended.
To install, unzip the archive and do the following:

```python
cd peekapp
python setup.py install
```

`peekapp --help` will print an overview of arguments and subcommands.
A logfile must be specified, and no packets will be logged without
one or more blacklist files specified as options.
Finally, a subcommand, either `iface` or `pcap` must be selected
in order to monitor a network interface or a PCAP-format packet dump,
respectively.
The interface or packet dump to be analyzed is to be specified
as the only argument to the selected subcommand.

To use the `iface` subcommand, peekapp must be run with root privileges.
This makes the interface slightly cumbersome if peekapp is installed
to a virtual environment or Python installation
that is not normally in ROOT's Python path,
but it is certainly preferable to installing peekapp via the system Python
installation.

Examples:
```bash
# Execute peekapp with root privileges using installed executable
sudo `which peekapp` -l out.log -d bad_domains.cfg -s sketchy_signatures.cfg iface wlan0

# Execute included script using Python install of the current (non-root) user
sudo `which python` peekapp.py -l out.log -d bad_domains.cfg -s sketchy_signatures.cfg iface wlan0

# Static analysis is a bit less complicated
peekapp -l out.log -i ips_that_should_be_reserved.cfg pcap oldtraffic.pcap

# Port scan detection on network interface
sudo `which peekapp` -p -l out.log iface eth0
```

### Configuration
TODO Different configuration file for each traffic type,
with the exception of port scan detection

Note that arbitrary byte sequences may be used when specifying
a configuration file listing payload signatures.
Non-character bytes must be specified via their two-digit hex encoding,
the format of which must comply with Python specification PEP 223.
In short, record the two-digit hex number `HH` as `\xHH`.
