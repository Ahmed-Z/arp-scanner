import scapy.all as scapy #import the scapy module
import argparse #import the argparse module

#define the function to scan the network
def scan(ip):
    arp_request = scapy.ARP(pdst=ip) #create an ARP request packet
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') #create a broadcast packet
    arp_request_broadcast = broadcast/arp_request #combine the ARP request and broadcast packet
    answered_list= scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0] #send the packet and store the response in a list
    return answered_list #return the response

#define the function to get the vendor of the given mac address
def get_mac_vendor(mac):
    mac = mac.upper().replace(':','')[0:6] #convert the mac address to upper case, remove the colons and get the first 6 characters
    with open("mac-vendor.txt","r") as f: #open the 'mac-vendor.txt' file in read mode
        for line in f : #iterate through the lines in the file
            if mac in line: #if the mac address is in the line
                return line[7:] #return the vendor name from the line
    return 'Unknown' #if the mac address is not found in the file, return 'Unknown'

#define the main function
def main():
    parser = argparse.ArgumentParser() #create a new ArgumentParser object
    parser.add_argument('-n','--network', type=str, required=True) #add a new argument 'network' which is required and is a string
    args = parser.parse_args() #parse the command line arguments
    hosts = scan(args.network) #scan the network and get the response
    for host in hosts: #iterate through the hosts in the response
        mac_vendor = get_mac_vendor(host[1].src).strip() #get the vendor of the host
        print(host[0].pdst + 2*'\t' + host[1].src + 2*'\t' + mac_vendor) #print the ip address, mac address and vendor of the host

if __name__ == "__main__":
    main() #call the main function
