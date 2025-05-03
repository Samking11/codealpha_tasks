import socket
import struct

def get_mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

def get_ipv4(addr):
    return '.'.join(map(str, addr))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_len = data[0]
    header_len = (version_header_len & 15) * 4
    src, target = struct.unpack('!4s4s', data[12:20])
    return get_ipv4(src), get_ipv4(target), data[header_len:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

# Create raw socket
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

print("Sniffing (Ethernet/IP/TCP)... Press Ctrl+C to stop.\n")

try:
    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        if eth_proto == 8:  # IPv4
            src_ip, dest_ip, ip_data = ipv4_packet(data)
            src_port, dest_port, sequence, acknowledgment, tcp_data = tcp_segment(ip_data)

            print(f"\nEthernet Frame:")
            print(f"  Source MAC: {src_mac}, Destination MAC: {dest_mac}")
            print(f"IPv4 Packet:")
            print(f"  Source IP: {src_ip}, Destination IP: {dest_ip}")
            print(f"TCP Segment:")
            print(f"  Src Port: {src_port}, Dest Port: {dest_port}, Seq: {sequence}, Ack: {acknowledgment}")
except KeyboardInterrupt:
    print("\nSniffing stopped.")
