import scapy.all as scapy
import argparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list


def get_mac_vendor(mac):
    mac = mac.upper().replace(':','')[0:6]
    with open("mac-vendor.txt","r") as f:
        for line in f :
            if mac in line:
                return line[7:]
    return 'Unknown' 


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n','--network', type=str, required=True)
    args = parser.parse_args()
    hosts = scan(args.network)
    for host in hosts:
        mac_vendor = get_mac_vendor(host[1].src).strip()
        print(host[0].pdst + 2*'\t' + host[1].src + 2*'\t' + mac_vendor)


if __name__ == "__main__":
    main()