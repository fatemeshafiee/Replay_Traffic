
from scapy.all import *
from threading import Thread
import sys
import random
import os
import time
import netifaces as ni


class Replay_Traffic(Thread):
    def __init__(self,sourceIP, destinationIP, pcap_file):
        Thread.__init__(self)
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        print("create the class")
        # self.sourcePort = sourcePort
        # self.destinationPort = destinationPort
        self.pcap_file = pcap_file
    def send_packet(self,sourceIP, destinationIP, pcap_file):
        print("in the send packet!!!")
        reader = PcapReader(pcap_file)
        pkt_count = 0

        last_timestamp = None
        for pkt in reader:
            pkt_count += 1
            # and new_pkt[IP].src == oldSource
            if IP in pkt :
                new_pkt = pkt.copy()
                new_pkt[IP].dst = destinationIP
                new_pkt[IP].src = sourceIP
                # new_pkt[IP].sport = int(sourcePort)
                # new_pkt[IP].dport = int(destinationPort)
                del new_pkt[IP].chksum
                if TCP in new_pkt:
                    del new_pkt[TCP].chksum
                elif UDP in new_pkt:
                    del new_pkt[UDP].chksum

                if last_timestamp is not None: 
                    delay = float(pkt.time) - float(last_timestamp)
                    time.sleep(delay)
                last_timestamp = pkt.time

                fragments = fragment(new_pkt, fragsize=1500)
                for frag in fragments:
                    sendp(frag, iface="eth1",verbose=False)
                    print("sent a packet")

        print(f"Total packets sent: {pkt_count}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python traffic_replay_frag.py sourceIP destinationIP")
        sys.exit(1)

    sourceIP = sys.argv[1]
    destinationIP = sys.argv[2]
    is_attack = sys.argv[3]
    threads = [] #added later


    try:
        ifname = "eth1"
        addr = ni.ifaddresses(ifname)
        if is_attack == 1:
            pcap_dir = "../ddos-data-sets-2022/benign_traffic"
            pcap_files = os.listdir(os.path.join(pcap_dir))
            if not pcap_files:
                print(f"No pcap files found for traffic type. Skipping...")
                
        else: 
            pcap_dir = "ddos-data-sets-2022/attack_traffic/tcpsyn"
            pcap_files = os.listdir(os.path.join(pcap_dir))
            if not pcap_files:
                print(f"No pcap files found for traffic type. Skipping...")
                
    except:
        pass
    #exit()
    print("before the for")
    for pcap_file in pcap_files:
        print("in the for")
        full_pcap_path = os.path.join(pcap_dir, pcap_file)
        print(full_pcap_path)
        traffic_generator = Replay_Traffic(sourceIP, destinationIP,full_pcap_path)
        traffic_generator.send_packet(sourceIP, destinationIP,full_pcap_path)
        threads.append(traffic_generator)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print("All traffic has been processed.")
