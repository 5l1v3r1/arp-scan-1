import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range.")
    options = parser.parse_args()

    return options

def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    list_of_clients = []

    for i in answered:
        client_dict = {'ip': i[1].psrc, 'mac': i[1].hwsrc}
        list_of_clients.append(client_dict)

    return list_of_clients
def print_result(results_list):

    print('IP\t\t\tMAC Address\n-------------------------------------------')
    for i in results_list:
        print(results_list[0]['ip'] + "\t\t" + results_list[1]['mac'])

    scapy.ls(scapy.ARP())

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
