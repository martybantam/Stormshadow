# Stormshadow
A python based framework to emulate UDP DDoS attacks

Usage:

The program receives udp packets from a Linux nfqueue (default 1, but configurable). It then rewrites source ip address and ports prior to returning the packet to the nfqueue for onward transmission

Parameters

--iprange   Range of IPV4 addresses from which the source addresses can be selected ( default 10.10.10.0/25)

-v          Verbose mode, enables verbose output including elapsed times for packets inside Stormshadow and address translations (default disabled)

--mode      Mode 1 : Source IP addresses selected at random from iprange, Mode 2 Source IP addresses selected on a round robin basis (default 1)

--seed      Seed for random number generator, can be used to enforce deterministic sequences (default time of day)

--port-mode  UDP port numbers can be (1) Preserved (2) Selected at random


