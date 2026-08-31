# Stormshadow
A python based framework to emulate UDP DDoS attacks

Usage:

The program receives udp packets from a Linux nfqueue (default 1, but configurable). It then rewrites source ip address and ports prior to returning the packet to the nfqueue for onward transmission.

Typically packets are directed towards Stormshadow by sending packets of interest to the chosen nfqueue

eg

sudo iptables -I OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1

to monitor usage

sudo iptables -L OUTPUT -n -v --line-numbers

to cancel

sudo iptables -D OUTPUT -p udp --dport 5060 -j NFQUEUE --queue-num 1


Parameters

--iprange   Range of IPV4 addresses from which the source addresses can be selected ( default 10.10.10.0/25)

-v          Verbose mode, enables verbose output including elapsed times for packets inside Stormshadow and address translations (default disabled)

--mode      Mode 1 : Source IP addresses selected at random from iprange, Mode 2 Source IP addresses selected on a round robin basis (default 1)

--seed      Seed for random number generator, can be used to enforce deterministic sequences (default time of day)

--port-mode  UDP port numbers can be (0) Preserved (1) Selected at random (2) Derived from generated source ip address (default 2)

--nfqueue    Linux nfqueue from which udp packets are derived and returned to






