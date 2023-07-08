# bcast-forward-pcap

bcast-forward-pcap is a command line tool that forwards UDP broadcast packets
with destination IP `255.255.255.255` received on a network interface to a
specified list of unicast addresses possibly on other network interfaces. For
example, it can be used for playing old LAN games, that use broadcasts to
discover game servers, over a VPN tunnel. bcast-forward-pcap uses pcap for
receiving and sending packets. For an IP/UDP raw socket version, see
[bcast-forward](https://github.com/hwipl/bcast-forward/).

## Installation

You can download and install bcast-forward-pcap with its dependencies to your
GOPATH or GOBIN with the go tool:

```console
$ go install github.com/hwipl/bcast-forward-pcap/cmd/bcast-forward-pcap
```

Note: you also need to have (lib)pcap installed on your system to use
bcast-forward-pcap.

## Usage

You can run `bcast-forward-pcap` with the following command line arguments:

```
  -d IPs
        forward broadcast packets to this comma-separated list of IPs, e.g.,
        "192.168.1.1,192.168.1.2"
  -i interface
        read packets from this network interface
  -keep-source-ip
        keep source address
  -p port
        only forward packets with this destination port (default 6112)
  -s IP
        rewrite source address to this IP
```

By default, bcast-forward-pcap rewrites the source IP address in forwarded
packets to an IP address that is determined by the forwarding host's routing to
each destination unicast address, usually an address of the outgoing network
interface. Alternatively, you can specify a single IP address with `-s` that
will be used as source IP address for all destination addresses. If you want to
keep the original sender's IP address, you can disable source IP address
rewriting completely with `-keep-source-ip`.
