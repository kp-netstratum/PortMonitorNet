# import pyshark
# from collections import defaultdict, Counter
# from typing import Dict, List, Any
# import time
# from datetime import datetime

# class PCAPAnalyzer:
#     def __init__(self, pcap_file_path: str):
#         self.pcap_file_path = pcap_file_path
#         self.capture = None
    
#     def load_capture(self):
#         """Load the PCAP file using PyShark"""
#         try:
#             self.capture = pyshark.FileCapture(self.pcap_file_path, keep_packets=False)
#             return True
#         except Exception as e:
#             self.capture = None
#             raise RuntimeError(
#                 f"Failed to load PCAP '{self.pcap_file_path}': {e}. "
#                 "Ensure the file is a valid PCAP and that Wireshark/TShark is installed."
#             )
    
#     def get_basic_stats(self) -> Dict[str, Any]:
#         """Get basic statistics about the PCAP file"""
#         if not self.capture:
#             self.load_capture()
#         if self.capture is None:
#             raise RuntimeError("Capture is not loaded; cannot compute basic stats.")
        
#         stats = {
#             "total_packets": 0,
#             "protocols": Counter(),
#             "src_ips": Counter(),
#             "dst_ips": Counter(),
#             "src_ports": Counter(),
#             "dst_ports": Counter(),
#             "packet_sizes": [],
#             "time_range": {"start": None, "end": None}
#         }
        
#         try:
#             for packet in self.capture:
#                 stats["total_packets"] += 1
                
#                 # Safely get packet length
#                 try:
#                     packet_length = int(packet.length)
#                     stats["packet_sizes"].append(packet_length)
#                 except (AttributeError, ValueError):
#                     stats["packet_sizes"].append(0)
                
#                 # Time range - use sniff_time if available, otherwise sniff_timestamp
#                 try:
#                     if hasattr(packet, 'sniff_time'):
#                         timestamp = packet.sniff_time.timestamp()
#                     elif hasattr(packet, 'sniff_timestamp'):
#                         timestamp = float(packet.sniff_timestamp)
#                     else:
#                         timestamp = time.time()  # Fallback
                    
#                     if stats["time_range"]["start"] is None:
#                         stats["time_range"]["start"] = timestamp
#                         stats["time_range"]["end"] = timestamp
#                     else:
#                         stats["time_range"]["start"] = min(stats["time_range"]["start"], timestamp)
#                         stats["time_range"]["end"] = max(stats["time_range"]["end"], timestamp)
#                 except (AttributeError, ValueError):
#                     pass
                
#                 # Protocol analysis
#                 try:
#                     if hasattr(packet, 'transport_layer') and packet.transport_layer:
#                         stats["protocols"][packet.transport_layer] += 1
#                     elif hasattr(packet, 'highest_layer') and packet.highest_layer:
#                         stats["protocols"][packet.highest_layer] += 1
#                     else:
#                         stats["protocols"]["Unknown"] += 1
#                 except AttributeError:
#                     stats["protocols"]["Unknown"] += 1
                
#                 # IP analysis
#                 try:
#                     if hasattr(packet, 'ip'):
#                         stats["src_ips"][packet.ip.src] += 1
#                         stats["dst_ips"][packet.ip.dst] += 1
#                 except AttributeError:
#                     pass
                
#                 # Port analysis (TCP/UDP)
#                 try:
#                     if hasattr(packet, 'tcp'):
#                         stats["src_ports"][int(packet.tcp.srcport)] += 1
#                         stats["dst_ports"][int(packet.tcp.dstport)] += 1
#                     elif hasattr(packet, 'udp'):
#                         stats["src_ports"][int(packet.udp.srcport)] += 1
#                         stats["dst_ports"][int(packet.udp.dstport)] += 1
#                 except (AttributeError, ValueError):
#                     pass
        
#         except Exception as e:
#             raise RuntimeError(f"Error processing packets: {str(e)}")
        
#         # Convert counters to regular dicts and get top entries
#         stats["protocols"] = dict(stats["protocols"].most_common(10))
#         stats["src_ips"] = dict(stats["src_ips"].most_common(10))
#         stats["dst_ips"] = dict(stats["dst_ips"].most_common(10))
#         stats["src_ports"] = dict(stats["src_ports"].most_common(10))
#         stats["dst_ports"] = dict(stats["dst_ports"].most_common(10))
        
#         # Packet size statistics
#         if stats["packet_sizes"]:
#             stats["packet_size_stats"] = {
#                 "min": min(stats["packet_sizes"]),
#                 "max": max(stats["packet_sizes"]),
#                 "avg": round(sum(stats["packet_sizes"]) / len(stats["packet_sizes"]), 2)
#             }
#         else:
#             stats["packet_size_stats"] = {"min": 0, "max": 0, "avg": 0}
        
#         # Format timestamps as readable dates
#         if stats["time_range"]["start"]:
#             stats["time_range"]["start_readable"] = datetime.fromtimestamp(stats["time_range"]["start"]).isoformat()
#             stats["time_range"]["end_readable"] = datetime.fromtimestamp(stats["time_range"]["end"]).isoformat()
#             stats["time_range"]["duration_seconds"] = round(stats["time_range"]["end"] - stats["time_range"]["start"], 2)
        
#         return stats
    
#     def get_conversations(self) -> List[Dict[str, Any]]:
#         """Extract network conversations (flows)"""
#         # Create new capture for conversations analysis
#         try:
#             capture = pyshark.FileCapture(self.pcap_file_path, keep_packets=False)
#         except Exception as e:
#             raise RuntimeError(f"Failed to create capture for conversations: {e}")
        
#         conversations = defaultdict(lambda: {
#             "packets": 0,
#             "bytes": 0,
#             "start_time": None,
#             "end_time": None,
#             "protocols": set()
#         })
        
#         try:
#             for packet in capture:
#                 # Get timestamp safely
#                 try:
#                     if hasattr(packet, 'sniff_time'):
#                         timestamp = packet.sniff_time.timestamp()
#                     elif hasattr(packet, 'sniff_timestamp'):
#                         timestamp = float(packet.sniff_timestamp)
#                     else:
#                         continue  # Skip packets without timestamps
#                 except (AttributeError, ValueError):
#                     continue
                
#                 if hasattr(packet, 'ip'):
#                     try:
#                         # Create conversation key (sorted IPs for bidirectional flows)
#                         src_ip = packet.ip.src
#                         dst_ip = packet.ip.dst
#                         conv_key = f"{min(src_ip, dst_ip)} <-> {max(src_ip, dst_ip)}"
                        
#                         conv = conversations[conv_key]
#                         conv["packets"] += 1
                        
#                         # Get packet size safely
#                         try:
#                             conv["bytes"] += int(packet.length)
#                         except (AttributeError, ValueError):
#                             pass
                        
#                         # Add protocol
#                         if hasattr(packet, 'highest_layer') and packet.highest_layer:
#                             conv["protocols"].add(packet.highest_layer)
                        
#                         # Update time range
#                         if conv["start_time"] is None:
#                             conv["start_time"] = timestamp
#                             conv["end_time"] = timestamp
#                         else:
#                             conv["start_time"] = min(conv["start_time"], timestamp)
#                             conv["end_time"] = max(conv["end_time"], timestamp)
                            
#                     except AttributeError:
#                         continue  # Skip packets without proper IP info
        
#         except Exception as e:
#             raise RuntimeError(f"Error processing conversations: {str(e)}")
        
#         finally:
#             try:
#                 capture.close()
#             except Exception:
#                 pass
        
#         # Convert to list and clean up
#         result = []
#         for conv_key, conv_data in conversations.items():
#             conv_data["conversation"] = conv_key
#             conv_data["protocols"] = list(conv_data["protocols"])
#             if conv_data["start_time"] and conv_data["end_time"]:
#                 conv_data["duration"] = round(conv_data["end_time"] - conv_data["start_time"], 2)
#                 conv_data["start_time_readable"] = datetime.fromtimestamp(conv_data["start_time"]).isoformat()
#                 conv_data["end_time_readable"] = datetime.fromtimestamp(conv_data["end_time"]).isoformat()
#             else:
#                 conv_data["duration"] = 0
#             result.append(conv_data)
        
#         # Sort by number of packets (descending)
#         result.sort(key=lambda x: x["packets"], reverse=True)
#         return result[:20]  # Return top 20 conversations
    
#     def get_suspicious_activity(self) -> Dict[str, Any]:
#         """Identify potentially suspicious network activity"""
#         # Create new capture for suspicious activity analysis
#         try:
#             capture = pyshark.FileCapture(self.pcap_file_path, keep_packets=False)
#         except Exception as e:
#             raise RuntimeError(f"Failed to create capture for suspicious activity: {e}")
        
#         suspicious = {
#             "port_scans": [],
#             "large_packets": [],
#             "unusual_protocols": [],
#             "high_volume_ips": []
#         }
        
#         ip_port_attempts = defaultdict(set)
#         protocol_counts = Counter()
#         ip_packet_counts = Counter()
        
#         try:
#             for packet in capture:
#                 # Get packet size safely
#                 try:
#                     packet_size = int(packet.length)
#                 except (AttributeError, ValueError):
#                     packet_size = 0
                
#                 # Large packets (> 1500 bytes)
#                 if packet_size > 1500:
#                     try:
#                         timestamp = packet.sniff_time.timestamp() if hasattr(packet, 'sniff_time') else float(packet.sniff_timestamp)
#                     except (AttributeError, ValueError):
#                         timestamp = 0
                    
#                     suspicious["large_packets"].append({
#                         "size": packet_size,
#                         "timestamp": timestamp,
#                         "src": getattr(packet.ip, 'src', 'Unknown') if hasattr(packet, 'ip') else 'Unknown',
#                         "dst": getattr(packet.ip, 'dst', 'Unknown') if hasattr(packet, 'ip') else 'Unknown'
#                     })
                
#                 # Protocol analysis
#                 try:
#                     protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else 'Unknown'
#                     protocol_counts[protocol] += 1
#                 except AttributeError:
#                     protocol_counts['Unknown'] += 1
                
#                 # IP packet counting and port scan detection
#                 if hasattr(packet, 'ip'):
#                     try:
#                         src_ip = packet.ip.src
#                         ip_packet_counts[src_ip] += 1
                        
#                         # Port scan detection
#                         dst_port = None
#                         if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
#                             dst_port = int(packet.tcp.dstport)
#                         elif hasattr(packet, 'udp') and hasattr(packet.udp, 'dstport'):
#                             dst_port = int(packet.udp.dstport)
                        
#                         if dst_port:
#                             ip_port_attempts[src_ip].add(dst_port)
#                     except (AttributeError, ValueError):
#                         pass
        
#         except Exception as e:
#             raise RuntimeError(f"Error analyzing suspicious activity: {str(e)}")
        
#         finally:
#             try:
#                 capture.close()
#             except Exception:
#                 pass
        
#         # Identify port scans (IPs accessing many different ports)
#         for ip, ports in ip_port_attempts.items():
#             if len(ports) > 10:  # Threshold for potential port scan
#                 suspicious["port_scans"].append({
#                     "src_ip": ip,
#                     "ports_accessed": len(ports),
#                     "ports": sorted(list(ports))[:20]  # Show first 20 ports
#                 })
        
#         # High volume IPs
#         total_packets = sum(ip_packet_counts.values())
#         if total_packets > 0:
#             for ip, count in ip_packet_counts.most_common(5):
#                 if count > total_packets * 0.1:  # More than 10% of total traffic
#                     suspicious["high_volume_ips"].append({
#                         "ip": ip,
#                         "packet_count": count,
#                         "percentage": round((count / total_packets) * 100, 2)
#                     })
        
#         # Unusual protocols (low frequency)
#         total_protocol_packets = sum(protocol_counts.values())
#         if total_protocol_packets > 0:
#             for protocol, count in protocol_counts.items():
#                 if count < total_protocol_packets * 0.01 and count > 0:  # Less than 1% but present
#                     suspicious["unusual_protocols"].append({
#                         "protocol": protocol,
#                         "count": count,
#                         "percentage": round((count / total_protocol_packets) * 100, 2)
#                     })
        
#         return suspicious
    
#     def close(self):
#         """Close the capture file"""
#         if self.capture:
#             try:
#                 self.capture.close()
#             except Exception:
#                 pass  # Ignore errors when closing

# # Synchronous analysis function that can be called directly
# def analyze_pcap_sync(pcap_file_path: str) -> Dict[str, Any]:
#     """Synchronous PCAP analysis"""
#     analyzer = PCAPAnalyzer(pcap_file_path)
#     try:
#         basic_stats = analyzer.get_basic_stats()
#         conversations = analyzer.get_conversations()
#         suspicious = analyzer.get_suspicious_activity()
        
#         return {
#             "basic_stats": basic_stats,
#             "conversations": conversations,
#             "suspicious_activity": suspicious
#         }
#     finally:
#         analyzer.close()

# # Async wrapper that doesn't use thread executor
# async def pysharkAnalysis(pcap_file_path: str) -> Dict[str, Any]:
#     """Analyze PCAP file using PyShark - direct async call"""
#     try:
#         return analyze_pcap_sync(pcap_file_path)
#     except Exception as e:
#         raise RuntimeError(f"PCAP analysis failed: {str(e)}")


from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict, Counter
from typing import Dict, List, Any
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=4)

class PCAPAnalyzer:
    def __init__(self, pcap_file_path: str):
        self.pcap_file_path = pcap_file_path
        self.packets = None
    
    def load_capture(self):
        """Load the PCAP file using Scapy"""
        try:
            self.packets = rdpcap(self.pcap_file_path)
            return True
        except Exception as e:
            self.packets = None
            raise RuntimeError(
                f"Failed to load PCAP '{self.pcap_file_path}': {e}. "
                "Ensure the file is a valid PCAP file."
            )
    
    def get_basic_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the PCAP file"""
        if not self.packets:
            self.load_capture()
        if self.packets is None:
            raise RuntimeError("Capture is not loaded; cannot compute basic stats.")
        
        stats = {
            "total_packets": len(self.packets),
            "protocols": Counter(),
            "src_ips": Counter(),
            "dst_ips": Counter(),
            "src_ports": Counter(),
            "dst_ports": Counter(),
            "packet_sizes": [],
            "time_range": {"start": None, "end": None}
        }
        
        try:
            for packet in self.packets:
                # Packet size
                packet_length = len(packet)
                stats["packet_sizes"].append(packet_length)
                
                # Time range
                try:
                    timestamp = float(packet.time)
                    if stats["time_range"]["start"] is None:
                        stats["time_range"]["start"] = timestamp
                        stats["time_range"]["end"] = timestamp
                    else:
                        stats["time_range"]["start"] = min(stats["time_range"]["start"], timestamp)
                        stats["time_range"]["end"] = max(stats["time_range"]["end"], timestamp)
                except (AttributeError, ValueError):
                    pass
                
                # Protocol analysis
                if packet.haslayer(TCP):
                    stats["protocols"]["TCP"] += 1
                elif packet.haslayer(UDP):
                    stats["protocols"]["UDP"] += 1
                elif packet.haslayer(IP):
                    stats["protocols"]["IP"] += 1
                else:
                    # Get the top layer name
                    top_layer = packet.lastlayer().__class__.__name__
                    stats["protocols"][top_layer] += 1
                
                # IP analysis
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    stats["src_ips"][ip_layer.src] += 1
                    stats["dst_ips"][ip_layer.dst] += 1
                
                # Port analysis
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    stats["src_ports"][tcp_layer.sport] += 1
                    stats["dst_ports"][tcp_layer.dport] += 1
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    stats["src_ports"][udp_layer.sport] += 1
                    stats["dst_ports"][udp_layer.dport] += 1
        
        except Exception as e:
            raise RuntimeError(f"Error processing packets: {str(e)}")
        
        # Convert counters to regular dicts and get top entries
        stats["protocols"] = dict(stats["protocols"].most_common(10))
        stats["src_ips"] = dict(stats["src_ips"].most_common(10))
        stats["dst_ips"] = dict(stats["dst_ips"].most_common(10))
        stats["src_ports"] = dict(stats["src_ports"].most_common(10))
        stats["dst_ports"] = dict(stats["dst_ports"].most_common(10))
        
        # Packet size statistics
        if stats["packet_sizes"]:
            stats["packet_size_stats"] = {
                "min": min(stats["packet_sizes"]),
                "max": max(stats["packet_sizes"]),
                "avg": round(sum(stats["packet_sizes"]) / len(stats["packet_sizes"]), 2)
            }
        else:
            stats["packet_size_stats"] = {"min": 0, "max": 0, "avg": 0}
        
        # Format timestamps as readable dates
        if stats["time_range"]["start"]:
            stats["time_range"]["start_readable"] = datetime.fromtimestamp(stats["time_range"]["start"]).isoformat()
            stats["time_range"]["end_readable"] = datetime.fromtimestamp(stats["time_range"]["end"]).isoformat()
            stats["time_range"]["duration_seconds"] = round(stats["time_range"]["end"] - stats["time_range"]["start"], 2)
        
        return stats
    
    def get_conversations(self) -> List[Dict[str, Any]]:
        """Extract network conversations (flows)"""
        if not self.packets:
            self.load_capture()
        if self.packets is None:
            raise RuntimeError("Capture is not loaded; cannot extract conversations.")
        
        conversations = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "start_time": None,
            "end_time": None,
            "protocols": set()
        })
        
        try:
            for packet in self.packets:
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    
                    # Get timestamp safely
                    try:
                        timestamp = float(packet.time)
                    except (AttributeError, ValueError):
                        continue  # Skip packets without timestamps
                    
                    # Create conversation key (sorted IPs for bidirectional flows)
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    conv_key = f"{min(src_ip, dst_ip)} <-> {max(src_ip, dst_ip)}"
                    
                    conv = conversations[conv_key]
                    conv["packets"] += 1
                    conv["bytes"] += len(packet)
                    
                    # Add protocol
                    if packet.haslayer(TCP):
                        conv["protocols"].add("TCP")
                    elif packet.haslayer(UDP):
                        conv["protocols"].add("UDP")
                    else:
                        conv["protocols"].add("IP")
                    
                    # Update time range
                    if conv["start_time"] is None:
                        conv["start_time"] = timestamp
                        conv["end_time"] = timestamp
                    else:
                        conv["start_time"] = min(conv["start_time"], timestamp)
                        conv["end_time"] = max(conv["end_time"], timestamp)
        
        except Exception as e:
            raise RuntimeError(f"Error processing conversations: {str(e)}")
        
        # Convert to list and clean up
        result = []
        for conv_key, conv_data in conversations.items():
            conv_data["conversation"] = conv_key
            conv_data["protocols"] = list(conv_data["protocols"])
            if conv_data["start_time"] and conv_data["end_time"]:
                conv_data["duration"] = round(conv_data["end_time"] - conv_data["start_time"], 2)
                conv_data["start_time_readable"] = datetime.fromtimestamp(conv_data["start_time"]).isoformat()
                conv_data["end_time_readable"] = datetime.fromtimestamp(conv_data["end_time"]).isoformat()
            else:
                conv_data["duration"] = 0
            result.append(conv_data)
        
        # Sort by number of packets (descending)
        result.sort(key=lambda x: x["packets"], reverse=True)
        return result[:20]  # Return top 20 conversations
    
    def get_suspicious_activity(self) -> Dict[str, Any]:
        """Identify potentially suspicious network activity"""
        if not self.packets:
            self.load_capture()
        if self.packets is None:
            raise RuntimeError("Capture is not loaded; cannot analyze suspicious activity.")
        
        suspicious = {
            "port_scans": [],
            "large_packets": [],
            "unusual_protocols": [],
            "high_volume_ips": []
        }
        
        ip_port_attempts = defaultdict(set)
        protocol_counts = Counter()
        ip_packet_counts = Counter()
        
        try:
            for packet in self.packets:
                packet_size = len(packet)
                
                # Large packets (> 1500 bytes)
                if packet_size > 1500:
                    try:
                        timestamp = float(packet.time)
                    except (AttributeError, ValueError):
                        timestamp = 0
                    
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                    if packet.haslayer(IP):
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                    
                    suspicious["large_packets"].append({
                        "size": packet_size,
                        "timestamp": timestamp,
                        "src": src_ip,
                        "dst": dst_ip
                    })
                
                # Protocol analysis
                if packet.haslayer(TCP):
                    protocol_counts["TCP"] += 1
                elif packet.haslayer(UDP):
                    protocol_counts["UDP"] += 1
                elif packet.haslayer(IP):
                    protocol_counts["IP"] += 1
                else:
                    protocol_name = packet.lastlayer().__class__.__name__
                    protocol_counts[protocol_name] += 1
                
                # IP packet counting and port scan detection
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    ip_packet_counts[src_ip] += 1
                    
                    # Port scan detection
                    if packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        ip_port_attempts[src_ip].add(tcp_layer.dport)
                    elif packet.haslayer(UDP):
                        udp_layer = packet[UDP]
                        ip_port_attempts[src_ip].add(udp_layer.dport)
        
        except Exception as e:
            raise RuntimeError(f"Error analyzing suspicious activity: {str(e)}")
        
        # Identify port scans (IPs accessing many different ports)
        for ip, ports in ip_port_attempts.items():
            if len(ports) > 10:  # Threshold for potential port scan
                suspicious["port_scans"].append({
                    "src_ip": ip,
                    "ports_accessed": len(ports),
                    "ports": sorted(list(ports))[:20]  # Show first 20 ports
                })
        
        # High volume IPs
        total_packets = sum(ip_packet_counts.values())
        if total_packets > 0:
            for ip, count in ip_packet_counts.most_common(5):
                if count > total_packets * 0.1:  # More than 10% of total traffic
                    suspicious["high_volume_ips"].append({
                        "ip": ip,
                        "packet_count": count,
                        "percentage": round((count / total_packets) * 100, 2)
                    })
        
        # Unusual protocols (low frequency)
        total_protocol_packets = sum(protocol_counts.values())
        if total_protocol_packets > 0:
            for protocol, count in protocol_counts.items():
                if count < total_protocol_packets * 0.01 and count > 0:  # Less than 1% but present
                    suspicious["unusual_protocols"].append({
                        "protocol": protocol,
                        "count": count,
                        "percentage": round((count / total_protocol_packets) * 100, 2)
                    })
        
        return suspicious

    def get_packet_table_rows(self, max_rows: int | None = None) -> List[Dict[str, Any]]:
        """Build table rows for packets: No., Time, Source, Destination, Protocol, Length, Info

        - Time is relative to the first packet (seconds, 6 decimal places)
        - Protocol is determined by TCP/UDP/IP else top-most layer name
        - Info summarizes key details based on protocol
        """
        if not self.packets:
            self.load_capture()
        if self.packets is None:
            raise RuntimeError("Capture is not loaded; cannot build table rows.")

        rows: List[Dict[str, Any]] = []

        if len(self.packets) == 0:
            return rows

        try:
            first_time = float(self.packets[0].time)
        except Exception:
            first_time = None

        try:
            for index, packet in enumerate(self.packets, start=1):
                # Time (relative if possible) and absolute timestamp
                try:
                    pkt_time = float(packet.time)
                    if first_time is not None:
                        rel_time = round(pkt_time - first_time, 6)
                    else:
                        rel_time = round(pkt_time, 6)
                    try:
                        timestamp_str = datetime.fromtimestamp(pkt_time).isoformat()
                    except Exception:
                        timestamp_str = ""
                except Exception:
                    rel_time = 0.0
                    timestamp_str = ""

                # Protocol determination
                if packet.haslayer(TCP):
                    protocol_name = "TCP"
                elif packet.haslayer(UDP):
                    protocol_name = "UDP"
                elif packet.haslayer(IP):
                    protocol_name = "IP"
                else:
                    try:
                        protocol_name = packet.lastlayer().__class__.__name__
                    except Exception:
                        protocol_name = "Unknown"

                # IP layer fields
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                else:
                    src_ip = "-"
                    dst_ip = "-"

                # Length
                try:
                    length_value = len(packet)
                except Exception:
                    length_value = 0

                # Info string
                info_parts: List[str] = []
                try:
                    if packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        sport = getattr(tcp_layer, "sport", None)
                        dport = getattr(tcp_layer, "dport", None)
                        flags = getattr(tcp_layer, "flags", None)
                        seq = getattr(tcp_layer, "seq", None)
                        ack = getattr(tcp_layer, "ack", None)
                        parts = []
                        if sport is not None and dport is not None:
                            parts.append(f"{sport} → {dport}")
                        if flags is not None:
                            parts.append(f"Flags: {flags}")
                        if seq is not None:
                            parts.append(f"Seq={seq}")
                        if ack is not None:
                            parts.append(f"Ack={ack}")
                        info_parts.append("; ".join(parts) if parts else "TCP segment")
                    elif packet.haslayer(UDP):
                        udp_layer = packet[UDP]
                        sport = getattr(udp_layer, "sport", None)
                        dport = getattr(udp_layer, "dport", None)
                        if sport is not None and dport is not None:
                            info_parts.append(f"{sport} → {dport}")
                        else:
                            info_parts.append("UDP datagram")
                    elif packet.haslayer(IP):
                        info_parts.append("IP packet")
                    else:
                        try:
                            info_parts.append(packet.summary())
                        except Exception:
                            info_parts.append("Packet")
                except Exception:
                    info_parts.append("Packet")

                info_value = "; ".join([p for p in info_parts if p])

                rows.append({
                    "no": index,
                    "time": rel_time,
                    "timestamp": timestamp_str,
                    "source": src_ip,
                    "destination": dst_ip,
                    "protocol": protocol_name,
                    "length": length_value,
                    "info": info_value,
                })

                if max_rows is not None and len(rows) >= max_rows:
                    break

        except Exception as e:
            raise RuntimeError(f"Error building packet table: {str(e)}")

        return rows

# Synchronous analysis function using Scapy
def analyze_pcap_sync(pcap_file_path: str) -> Dict[str, Any]:
    """Synchronous PCAP analysis using Scapy"""
    analyzer = PCAPAnalyzer(pcap_file_path)
    try:
        basic_stats = analyzer.get_basic_stats()
        conversations = analyzer.get_conversations()
        suspicious = analyzer.get_suspicious_activity()
        alldata = analyzer.get_packet_table_rows()
        
        return {
            "basic_stats": basic_stats,
            "conversations": conversations,
            "suspicious_activity": suspicious,
            "data": alldata
        }
    except Exception as e:
        raise RuntimeError(f"Analysis failed: {str(e)}")

# Async wrapper for FastAPI
async def pysharkAnalysis(pcap_file_path: str) -> Dict[str, Any]:
    """Analyze PCAP file - async wrapper around Scapy analysis"""
    def _analyze():
        return analyze_pcap_sync(pcap_file_path)
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, _analyze)