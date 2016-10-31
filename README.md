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
- [] Network port scanning activity

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
```

## Report
### Decision Process & Design
My entire networking background consists of what I've learned in the course
of studying for this class.
Hence, I chose the easy route and went with Python and Scapy.

I also used a couple of third-party libraries to ease
the development of the CLI and the test suite.
I opted for the Click module,
instead of the `argparse` module that ships with Python,
due to personal familiarity with Click.
It's treated me well in the past, and I still recommend it,
but this choice really hurt me, as I describe below.
Similarly, I went with PyTest instead of the stock Python choice, UnitTest,
in part out of familiarity.
I also don't mind the great fixture support, test discovery,
and relative lack of boilerplate code.

### Difficulties
For some reason, Click sent the `interface` argument to `sniff`
multiple times when calling `peekapp.interface.iface`.
The first time, `interface` was passed - correctly - as a string.
The second and third times, however, it was passed as unicode.

To procure L2 socket to listen on,
Scapy would eventually pass this argument into `struct.pack`,
which would crash everything since it expected `<type 'string'>`,
not `<type 'unicode'>`
This was rather difficult to discover, however,
due to the threading provided by `scapy.pipetool.PipeEngine`,
which resulted in unhelpful error messages.

To find the bug, I ultimately wrote my own pipes module
on top of `scapy.pipetool._ConnectorLogic`.
I was pretty happy with the results
until I moved the new code from my test script back into my application code
and was faced with the same error message.
I was finally able to debug what was happening in `scapy.arch.common.get_if`,
link it back to Click, and move on.

At this point, it was past noon on Saturday,
and I'd been at an impasse since Wednesday night.
I decided to keep my own pipes module
both for the sake of time
and to avoid debugging around PipeEngine's threads.
I would enjoy forking the project at a later date
to again try using `scapy.pipetool`,
but doing so would require a substantial rewrite of several components,
such as `peekapp.alerts`.

Despite getting an early start (see git logs,)
this greatly set me back in tackling the actual features of the project.
On the one hand, I could have tried implementing each feature independently
and glued it all together somehow.
Maybe there's a lesson to be learned here about priorities or something.
I would have preferred to have the extra time to
build a Vagrant testing environment, add TravisCI support for testing,
and start on port scan detection prior to 11:30 on Sunday night.
On the other hand, I was very happy with the architecture I had sketched out,
and I'm even happier now that it's functional.
As I've been hacking away on the actual features,
I've found the underlying application very nicely structured
for accommodating new changes.

### Limitations
I assume peekapp would perform better with threading support,
which I lost when I abandoned PipeEngine,
since logged packets will be doubly IO-bound.

I'm happy with the current alert system for monitoring in-flight packets.
However, this system's aggregation model is very much dependent
on the timestamps of packets, as well as the order in which they are received.
Hence, it is ill-suited for static analysis of a PCAP file
via the `pcap` command.
A stateless aggregation strategy of all packets within the file
would be more appropriate.
A parameterizable map-reduce (or, split-apply-combine) strategy
for summarizing static logs would make for a good feature addition.

TODO Port scan limitations

### Testing
To test the basic functionality of the application,
I first implemented logging of DNS queries.
Then, I built the alert system by trial and error,
checking for UDP packets bound for a small number of websites.

Once I was ready to add additional features,
I implemented a small number of functional tests for regression detection
using the PyTest module.
Each feature is tested against a PCAP file I produced using Wireshark.
Having prior knowledge of the features of each file produced
(documented in `peekapp/tests/files/README.md`,)
I was able to produce explicit tests.
Features are required to log the correct number of "bad" packets,
and all logged packets are checked for compliance
with the provided traffic rule(s).
After installation, the test suite can be run from
the topmost source directory via `python setup.py test`.

TODO Stress testing / testing under load

## Conclusion
TODO
