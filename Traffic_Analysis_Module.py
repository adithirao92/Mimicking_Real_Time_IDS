# from scapy.all import TCP, IP
# from collections import defaultdict

# class TrafficAnalyzer:
#     def __init__(self):
#         self.connections = defaultdict(list)
#         self.flow_stats = defaultdict(lambda: {
#             'packet_count': 0,
#             'byte_count': 0,
#             'start_time': None,
#             'last_time': None
#         })

#     def analyze_packet(self, packet):
#         if IP in packet and TCP in packet:
#             ip_src = packet[IP].src
#             ip_dst = packet[IP].dst
#             port_src = packet[TCP].sport
#             port_dst = packet[TCP].dport

#             flow_key = (ip_src, ip_dst, port_src, port_dst)

#             # Update flow statistics
#             stats = self.flow_stats[flow_key]
#             stats['packet_count'] += 1
#             stats['byte_count'] += len(packet)
#             current_time = packet.time

#             if not stats['start_time']:
#                 stats['start_time'] = current_time
#             stats['last_time'] = current_time

#             return self.extract_features(packet, stats)

#     def extract_features(self, packet, stats):
#         # Calculate flow duration
#         flow_duration = stats['last_time'] - stats['start_time']

#         # Prevent division by zero
#         if flow_duration > 0:
#             packet_rate = stats['packet_count'] / flow_duration
#             byte_rate = stats['byte_count'] / flow_duration
#         else:
#             packet_rate = 0
#             byte_rate = 0

#         return {
#             'packet_size': len(packet),
#             'flow_duration': flow_duration,
#             'packet_rate': packet_rate,
#             'byte_rate': byte_rate,
#             'tcp_flags': packet[TCP].flags,
#             'window_size': packet[TCP].window
#         }





from collections import defaultdict
from scapy.all import TCP, UDP, ICMP, IP
import time
from datetime import datetime

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })
        self.port_tracker = defaultdict(set) #tracks dest port accessed by each source port- useful for port scan

    def analyze_packet(self, packet):
        if hasattr(packet, 'haslayer') and packet.haslayer(IP) and packet.haslayer(TCP):
            flow_key = self._get_flow_key(packet)
            stats = self._update_flow_stats(flow_key, packet)
            return self._extract_features(packet, stats, flow_key)
        return None

    def _get_flow_key(self, packet):
        return (packet[IP].src, packet[IP].dst, 
                packet[TCP].sport, packet[TCP].dport)

    def _update_flow_stats(self, flow_key, packet):
        stats = self.flow_stats[flow_key]
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        
        timestamp = getattr(packet, 'timestamp', time.time())
        if not stats['start_time']:
            stats['start_time'] = timestamp
        stats['last_time'] = timestamp
        
        return stats

    def _detect_protocol(self, packet):
        """Detect the protocol of the packet"""
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:  #.dport and .sport are built in commands offered by scapy
                return 'http'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return 'https'
            return 'tcp'
        elif packet.haslayer(UDP):
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                return 'dns'
            return 'udp'
        elif packet.haslayer(ICMP):
            return 'icmp'
        return 'other'

    def _update_port_tracker(self, flow_key):
        """Track destination ports for scan detection"""
        src_ip, dst_ip, src_port, dst_port = flow_key
        self.port_tracker[src_ip].add(dst_port)
        return list(self.port_tracker[src_ip])  #returns a list of accessed ports

    def _cleanup_port_tracker(self, max_age=3600):
        """Remove old entries to prevent memory bloat"""
        current_time = time.time()
        for src_ip in list(self.port_tracker.keys()):
            # Simple cleanup
            if current_time - self.flow_stats.get((src_ip,), {}).get('last_time', 0) > max_age:
                del self.port_tracker[src_ip]

    def _extract_features(self, packet, stats, flow_key):
     duration = max(0.001, (stats['last_time'] - stats['start_time']).total_seconds())  #useful in calculating packet and byte rate - ensures it doesnt go below a specific threshold
    
     return {
        'packet_size': len(packet),
        'packet_rate': stats['packet_count'] / duration,
        'byte_rate': stats['byte_count'] / duration,
        'tcp_flags': str(packet[TCP].flags) if TCP in packet else None,
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'flow_duration': duration,
        'protocol': self._detect_protocol(packet),
        'dst_ports': self._update_port_tracker(flow_key)
    }   