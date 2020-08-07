from scapy.all import *
from scapy.layers import *
import os
import csv

# return mac address of packet
# return type: str
def return_mac_address(packet):
	return packet.getlayer(Ether).src

# return query name of dns packet
def return_dns_packet_qname(packet):
	return packet.getlayer(DNSQR).qname.decode('utf-8')

# return source of hppt packet
def return_http_packet_source(packet):
	return packet.getlayer(HTTP).Host.decode('utf-8')

# save data of new users
# just write on file
def save_data(file_path, user_dict):
	update_data = dict()
	with open(file_path, 'r') as csv_file:
		reader = csv.reader(csv_file)
		update_data = {data[0]:int(data[1]) for data in reader}
		print(update_data)
	
	for u in user_dict:
		if u in update_data:
			update_data[u] += user_dict[u]
		else:
			update_data[u] = user_dict[u]

	with open(file_path, 'w') as csv_file:
		writer = csv.writer(csv_file)
		for u in update_data:
			writer.writerow([u, update_data[u]])



load_layer("http") # load http layer
load_layer("dns") # load dns layer
load_layer('l2') # load ethernet layer -> for mac address
packets = rdpcap('packets.pcap') # read pcap file
http = 0 # count how many http packets are
dns = 0 # count how many dns packets are
index = 0 # count the order of packet

# dictionary user
# key: mac address
# value: dictionary
user = dict()
for packet in packets:
	index += 1
#ls(packet)
	if packet.haslayer(HTTP):
		print(packet.haslayer(HTTP))
		http += 1
		mac = packet.getlayer(Ether).src
		source = packet.getlayer(HTTP).Host.decode('utf-8')
		# if the user is new one create new dictionary in user dictionary
		if mac not in user:
			print('\n새로 추가된 mac'+mac)
			user[mac] = dict()

		if source not in user[mac]:
			user[mac][source] = 1
		else:
			user[mac][source] += 1


#print(packet.getlayer(Ether).src)
		print(str(index) + '번째 HTTP 패킷')
		print(packet.getlayer(HTTP).Host.decode('utf-8'))
	elif packet.haslayer(DNS) and False:
		dns += 1
		print(str(index) + '번째 DNS 패킷')
		if packet.haslayer(DNSQR):
			qr = packet.getlayer(DNSQR)
			print(qr.qname.decode('utf-8'))

print('총' + str(http) + '개의 HTTP 패킷')
print('총' + str(dns) + '개의 DNS 패킷')
# 만약 openwrt의 파일을 전송 받고 싶을 때
# os.system('scp root@192.168.1.1://tmp/dhcp.leases .')
#print(user)

# file에 작성하는 code 추가
for mac, user_dict in user.items():
	file_path = 'read_pcap_file/' + mac + '.csv'
	# if file doesn't exist, create new file
	if not os.path.isfile(file_path):
		f = open(file_path, 'w')
		f.close()
	# save the file -> create new function
	save_data(file_path, user_dict)	
#for i in user_dict.items():
#		print(i)
