from scapy.all import *
from scapy.layers.inet import *
from scapy.sendrecv import *

portsScan = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5000, 5900,
             8000, 8080]


# no deja spoofear la ip

def tcp_scan(dst_ip, dst_port):
    pkt = IP(src='10.0.1.8', dst=dst_ip) / TCP(dport=dst_port)
    ans, unans = sr(pkt, iface="tun0", timeout=5)

    if not ans:
        print(f"host {dst_ip} is offline")
    else:
        for snd, rcvd in ans:
            if rcvd[TCP].flags == "SA":
                print(f"Port {dst_port} on host {dst_ip} is open")
            else:
                print(f"port {dst_port} on host {dst_ip} is closed but the itself is alive")

    """print(tcp_connect_scan_resp)
    if str(type(tcp_connect_scan_resp)) == "<class 'NoneType'>":
        print("Closed")
    elif tcp_connect_scan_resp.haslayer("TCP"):
        if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:
            print("Open")
        elif tcp_connect_scan_resp.getlayer("TCP").flags == 0x14:
            print("Closed")"""


for port in portsScan:
    print("trying port {}".format(port))
    tcp_scan("10.0.1.6", port)
