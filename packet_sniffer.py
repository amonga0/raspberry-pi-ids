from scapy.all import sniff, IP, TCP, UDP # library for packet capture and dissection (focusing on IP, TCP, UDP)
from datetime import datetime # datetime for timestamping logs in terminal output
import csv # for writing to CSV files and displaying in  dashboard
import os # to check for file extensions

# initialize name of the CSV file where packet data will be logged (for output in terminal + dashboard)
CSV_FILE = "traffic_log.csv"

# initialize a list of suspicious destination ports to flag (e.g., outdated ports like Telnet)
suspicious_ports = [23, 2323, 31337]

# initialize a list of suspicious/unknown external IPs to flag
unknown_ips = ["172.129.172.108"]

# create CSV file and populate with columns
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline = '') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Service", "Size (bytets)", "Alert"])

# callback function to run everytime a packet is sniffed
def process_packet(packet):
    # packets that have an IP layer
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # timestamp for packet

        # default protocol labels and port values unless recognized by Scapy
        proto = "OTHER"
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = dst_port = "-"
        service = "-"
        size = len(packet)
        alert_msg = ""

        # if packet is TCP:
        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # if packet is UDP:
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # check for suspicious destination port
        if int(dst_port) in suspicious_ports:
            alert_msg = f"suspicious_port({dst_port})"

        # unknown source IP
        elif src_ip in unknown_ips:
            alert_msg = f"unknown_source_ip({src_ip})"
        
        # write data to CSV file
        with open(CSV_FILE, "a", newline = '') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, proto, src_ip, src_port, dst_ip, dst_port, service, size, alert_msg])

# start packet sniffing on Pi's wlan0
print("Sniffing started") # starting message for troubleshooting
sniff(iface="wlan0", prn=process_packet, store=False) # don't store packets in memory to save RAM