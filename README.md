# Stormshadow
A python based framework to emulate UDP DDoS attacks

Usage:

The program receives udp packets from a Linux nfqueue (default 1, but configurable). It then rewrites source ip address and ports prior to returning the packet to the nfqueue for onward transmission


