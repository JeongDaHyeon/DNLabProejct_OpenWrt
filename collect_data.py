import re
import sys
import os
import time
import csv
from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether

minutes = 5
folder = 'data'
pcap_file = 'packets.pcap'

def capture_packets():
	os.system('ssh root@192.168.1.1 "tcpdump -c 100 -i wlan0 -U -s0 -w - dst port 53 or 80" > packets.pcap')

# url: extracted url of a packet
def extract_domain_name(url):
    regex_domain_name = re.compile('[\w]+\.(com|net|co.kr)')
    domain_name = regex_domain_name.search(url)
    if domain_name:
        return domain_name.group()
    else: # url is out of the form of regular expression
        return False

def save_data(packets):
    for p in packets:
        domain_name = None
        if p.haslayer(HTTP):
            if 'Host' in str(p.getlayer(HTTP)):
                domain_name = extract_domain_name(p.getlayer(HTTP).Host.decode('utf-8'))
        # domain_name을 가져 올수 있을 때만 저장
        elif p.haslayer(DNSQR):
            domain_name = extract_domain_name(p.getlayer(DNSQR).qname.decode('utf-8'))

        if domain_name:
            timestamp = p.time
            mac = p.getlayer(Ether).src
            file_path = folder + '/' + mac + '.csv'
            # if file doesn't exit, create new file
            if not os.path.isfile(file_path):
                f = open(file_path, 'w')
                f.close()
            with open(file_path, 'a') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([domain_name, timestamp])

if __name__ == '__main__':
    os.system('rm -r ' + folder + '/*')
    # time_end: time of caturing packets
    time_end = time.time() + (60 * minutes)
    while True:
        capture_packets()
        packets = rdpcap(pcap_file)
        save_data(packets)
        if time.time() > time_end:
            break
