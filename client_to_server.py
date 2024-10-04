
from scapy.all import *
from threading import Thread
import sys
import random
import os
import time
import netifaces as ni


class Replay_Traffic(Thread):
    def __init__(self,sourceIP, destinationIP, oldSource, pcap_file):
        Thread.__init__(self)
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        self.oldSource = oldSource
        # self.sourcePort = sourcePort
        # self.destinationPort = destinationPort
        self.pcap_file = pcap_file
    def send_packet(self,sourceIP, destinationIP, oldSource, pcap_file):

        reader = PcapReader(pcap_file)
        pkt_count = 0

        last_timestamp = None
        for pkt in reader:
            pkt_count += 1
            if IP in pkt and new_pkt[IP].src == oldSource:
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

        print(f"Total packets sent: {pkt_count}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python traffic_replay_frag.py config.txt")
        sys.exit(1)

    config_path = sys.argv[1]
    threads = [] #added later

    with open(config_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) == 3:
                sourceIP, destinationIP, oldSource = parts

            try:
                ifname = "gtp-gnb"
                addr = ni.ifaddresses(ifname)
                sourceIP = "12.1.1.2"
                print(sourceIP)
                if sourceIP in ["12.1.1.2", "12.1.1.3", "12.1.1.4"]:
                    pcap_dir = "../ddos-data-sets-2022/benign_traffic"
                    pcap_files = os.listdir(os.path.join(pcap_dir))
                    if not pcap_files:
                        print(f"No pcap files found for traffic type. Skipping...")
                        continue
                else: 
                    pcap_dir = "../malicious"
                    pcap_files = os.listdir(os.path.join(pcap_dir))
                    if not pcap_files:
                        print(f"No pcap files found for traffic type. Skipping...")
                        continue



            except:
                pass
            #exit()

            for pcap_file in pcap_files:
                
                full_pcap_path = os.path.join(pcap_dir, pcap_file)
                print(full_pcap_path)
                traffic_generator = Replay_Traffic(sourceIP, destinationIP,oldSource,full_pcap_path)
                traffic_generator.send_packet()
                threads.append(traffic_generator)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print("All traffic has been processed.")
