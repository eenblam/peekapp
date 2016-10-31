## `hack.pcap`
I googled "stack overflow hack the mainframe,"
then clicked through the first few links.
Results were captured via wireshark with `http` display filter,
and displayed results were written to file.

IP addresses (count):

- 151.101.1.69 (166)
- 151.101.129.69 (153)
- 104.16.108.18 (3)
- 10.0.0.16 (319, all)

## `hack_ips.cfg`
Contains the following IP addresses to filter from `hack_urls.pcap`:

- 151.101.1.69
- 104.16.108.18

(Should total to 153 packets)

## `hack_url_rules.cfg`
URL rules for analysis of `hack.pcap`.
Should match how-to-hack before hack.

- how-to-hack (1)
- hack (5, due to order. Matches 6.)
 
## `icanhazip_or_pytest.pcap`
- 364 UDP packets, all with DNSQR layer
- 182 of the 364 do not have DNSRR layer

Domains:

- icanhazip.com (24 requests, 24 replies)
- doc.pytest.org (158 requests, 158 replies)

IP addresses:

- 10.0.0.16
- 127.0.1.1
- 10.0.0.1
- 127.0.0.1

## `icanhazip.cfg`
Contains only the domain `icanhazip.com`.

