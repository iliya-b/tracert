from icmplib import ping, multiping, traceroute, resolve, exceptions
from icmplib.sockets import ICMPv4Socket, ICMPv6Socket
from icmplib.models import ICMPRequest
from icmplib.exceptions import TimeExceeded, ICMPLibError
from time import sleep
from icmplib.utils import unique_identifier, is_hostname, is_ipv6_address, is_ipv4_address
from dns import reversename, resolver
import argparse

parser = argparse.ArgumentParser(
                    prog = 'Tracert',
                    description = 'Trace host using ICMP packets')

parser.add_argument('host', type=str, help="Host or IP address to trace")  
parser.add_argument('--no-dns', 
                    action='store_true', default=False, 
                    help="Do not show domain names")
args = parser.parse_args()

ttl = 1
host = args.host
no_dns = args.no_dns

if is_hostname(host):
    try:
        ip = resolve(host)[0]
    except exceptions.NameLookupError:
        print("Cannot resolve host")
        quit(-1)
else:
    ip = host

if is_ipv6_address(ip):
    _Socket = ICMPv6Socket
elif is_ipv4_address(ip):
    _Socket = ICMPv4Socket
else:
    print("Not a valid host or IP")
    quit(-1)

timeout = 0.05
max_hops = 30
host_reached=False
packet_size = 72
header_size = 8

id = unique_identifier()

print("traceroute to %s (%s), %d hops max, %d bytes packets" % (host, ip, max_hops, packet_size ))
with _Socket(None, privileged=False) as socket:
    while not host_reached and ttl <= max_hops:
        print(str(ttl).ljust(2), end=' ')
        reply = None
        host_shown = False
        for sequence in range(3):
            try:
                request = ICMPRequest(
                    destination=ip,
                    id=id,
                    sequence=sequence,
                    ttl=ttl,
                    payload_size=packet_size-header_size
                )
                socket.send(request)
                reply = socket.receive(request, timeout)
                rtt = (reply.time - request.time) * 1000
                host_reached = reply.source == ip
                if not host_shown:
                    if no_dns:
                        print(("%s" % (reply.source)).ljust(50), end="\t" )
                    else:
                        try:
                            hostname = str(resolver.resolve_address(reply.source)[0])
                        except:
                            hostname = reply.source
                        print(("%s (%s)" % (hostname, reply.source)).ljust(50), end="\t" )
                    host_shown = True
                print("%.03f ms" % rtt, end="\t")
                reply.raise_for_status()
            except TimeExceeded as e:
                sleep(timeout) 
            except ICMPLibError as e:
                print("*", end="\t")
                sleep(0.01)

        print('')

        ttl += 1