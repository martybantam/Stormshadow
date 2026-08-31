from scapy.all import *
from netfilterqueue import NetfilterQueue
import random
import ipaddress
import time
import argparse

ephemeral_start = 49152 
ephemeral_end = 65535 


RFC1918_space = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

print('Stormshadow may have a detrimental effect on devices targeted by this tool. It is intented as a training and testing tool')
print('Do not use it on any network without prior permission of the responsible partner. Stormshadow version 1.1 25 August 2026')

parser = argparse.ArgumentParser(
    description="Stormshadow source IP rewriting tool"
)

parser.add_argument(
    "--iprange",
    type=str,
    default="10.10.10.0/25",
    help="IP range/subnet used for source address generation (default: 10.10.10.0/25)"
)

parser.add_argument(
    "--mode",
    type=int,
    choices=[1, 2],
    default=1,
    help="Address selection mode: 1=random, 2=round-robin (default: 1)"
)

parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Enable verbose output (default: off)"
)

parser.add_argument(
    "--seed",
    type=int,
    default=-1,
    help="Seed value (default: -1)"
)

parser.add_argument(
    "--queue",
    type=int,
    default=1,
    help="NFQUEUE number (default: 1)"
)

parser.add_argument(
    "--portmode",
    type=int,
    choices=[0, 1, 2],
    default=2,
    help="Source port mode: 0=preserve, 1=random, 2=IP-mapped (default: 2)"
)

args = parser.parse_args()

cidr=ipaddress.ip_network(args.iprange)


num_hosts = cidr.num_addresses - 2
host_ptr = 0

# modes 1 = random, 2 = round robin

mode = args.mode


def is_rfc1918_subnet(network):
    return any(network.subnet_of(r) for r in RFC1918_space)

def port_from_ip(ip):
    ip_int = int(ipaddress.ip_address(ip))
    return ephemeral_start + (
        ip_int % (ephemeral_end - ephemeral_start + 1)
    )
    

def roundrobin_pull_ip():
    global host_ptr
    ip = cidr.network_address + 1 + host_ptr
    host_ptr = (host_ptr + 1) % num_hosts
    return ip


def random_pull_ip():
    host_offset = random.randint(1, cidr.num_addresses - 2)
    return cidr.network_address + host_offset



if args.seed == -1:
    rtime=time.time()
    print(' Seed : ',rtime)
    random.seed(rtime)
else:
    random.seed(args.seed)
    print('Seed : ', args.seed)

if args.mode == 1:
    print(' Mode : Random')
else:
    print(' Mode : Round Robin')
    

print(' IP Range : ', args.iprange)
if args.portmode == 0:
    print(' Source Port Mode : Preserve')
if args.portmode == 1:
    print(' Source Port Mode : Random')
if args.portmode == 2:
    print(' Source Port Mode : IP Mapped') 

if not is_rfc1918_subnet(cidr):
    print(f"ERROR: {args.iprange} is not an RFC1918 compliant subnet.")
    print("For security reasons, Stormshadow only supports private address ranges.")
    sys.exit(1)    

def modify_packet(pkt):
    global mode
    start_time = time.perf_counter()
    packet = IP(pkt.get_payload())
    if args.verbose:
        print(packet)
    if packet.haslayer(IP):
        if mode == 1:
             packet.src = str(random_pull_ip())
        elif mode == 2:
             packet.src = str(roundrobin_pull_ip())
        if args.portmode == 0:
            pass  # preserve original port
        elif args.portmode == 1:
            packet.sport = random.randint(ephemeral_start,ephemeral_end)
        elif args.portmode == 2:
            packet.sport = port_from_ip(packet.src)
        #del packet.chksum  # Recalculate checksum
        del packet[IP].chksum
        del packet[UDP].chksum
        if args.verbose:
             print(f"{packet.src}:{packet[UDP].sport}")
        elapsed_time = time.perf_counter() - start_time
        if args.verbose:
            print(' Elapsed time in side packet rewrite: ', elapsed_time)
        pkt.set_payload(bytes(packet))    
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(args.queue, modify_packet)
nfqueue.run()
