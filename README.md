# bcast-forward-pcap

bcast-forward-pcap is a command line tool that forwards UDP broadcast packets
with destination IP 255.255.255.255 received on a network interface to a
specified list of unicast addresses possibly on other network interfaces. For
example, it can be used for playing old LAN games, that use broadcasts to
discover game servers, over a VPN tunnel. bcast-forward-pcap uses pcap for
receiving and sending packets. For an IP/UDP raw sockets version, see
[bcast-forward](https://github.com/hwipl/bcast-forward/).

## Installation

You can download and install bcast-forward-pcap with its dependencies to your
GOPATH or GOBIN with the go tool:

```console
$ go get github.com/hwipl/bcast-forward-pcap/cmd/bcast-forward-pcap
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
  -p port
        only forward packets with this destination port (default 6112)
  -s IP
        rewrite source address to this IP
```
