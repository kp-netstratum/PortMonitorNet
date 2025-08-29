import asyncio
import pyshark
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter
from typing import Dict, List, Any
import time
from datetime import datetime

executor = ThreadPoolExecutor(max_workers=4)

class PCAPAnalyzer:
    def __init__(self, pcap_file_path: str):
        self.pcap_file_path = pcap_file_path
        self.capture = None
    
    def load_capture(self):
        """Load the PCAP file using PyShark"""
        try:
            self.capture = pyshark.FileCapture(self.pcap_file_path, keep_packets=False)
            return True
        except Exception as e:
            self.capture = None
            raise RuntimeError(
                f"Failed to load PCAP '{self.pcap_file_path}': {e}. "
                "Ensure the file is a valid PCAP and that Wireshark/TShark is installed."
            )
    
    def get_basic_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the PCAP file"""
        if not self.capture:
            self.load_capture()
        if self.capture is None:
            raise RuntimeError("Capture is not loaded; cannot compute basic stats.")
        
        stats = {
            "total_packets": 0,
            "protocols": Counter(),
            "src_ips": Counter(),
            "dst_ips": Counter(),
            "src_ports": Counter(),
            "dst_ports": Counter(),
            "packet_sizes": [],
            "time_range": {"start": None, "end": None}
        }
        
        try:
            for packet in self.capture:
                stats["total_packets"] += 1
                
                # Safely get packet length
                try:
                    packet_length = int(packet.length)
                    stats["packet_sizes"].append(packet_length)
                except (AttributeError, ValueError):
                    stats["packet_sizes"].append(0)
                
                # Time range - use sniff_time if available, otherwise sniff_timestamp
                try:
                    if hasattr(packet, 'sniff_time'):
                        timestamp = packet.sniff_time.timestamp()
                    elif hasattr(packet, 'sniff_timestamp'):
                        timestamp = float(packet.sniff_timestamp)
                    else:
                        timestamp = time.time()  # Fallback
                    
                    if stats["time_range"]["start"] is None:
                        stats["time_range"]["start"] = timestamp
                        stats["time_range"]["end"] = timestamp
                    else:
                        stats["time_range"]["start"] = min(stats["time_range"]["start"], timestamp)
                        stats["time_range"]["end"] = max(stats["time_range"]["end"], timestamp)
                except (AttributeError, ValueError):
                    pass
                
                # Protocol analysis
                try:
                    if hasattr(packet, 'transport_layer') and packet.transport_layer:
                        stats["protocols"][packet.transport_layer] += 1
                    elif hasattr(packet, 'highest_layer') and packet.highest_layer:
                        stats["protocols"][packet.highest_layer] += 1
                    else:
                        stats["protocols"]["Unknown"] += 1
                except AttributeError:
                    stats["protocols"]["Unknown"] += 1
                
                # IP analysis
                try:
                    if hasattr(packet, 'ip'):
                        stats["src_ips"][packet.ip.src] += 1
                        stats["dst_ips"][packet.ip.dst] += 1
                except AttributeError:
                    pass
                
                # Port analysis (TCP/UDP)
                try:
                    if hasattr(packet, 'tcp'):
                        stats["src_ports"][int(packet.tcp.srcport)] += 1
                        stats["dst_ports"][int(packet.tcp.dstport)] += 1
                    elif hasattr(packet, 'udp'):
                        stats["src_ports"][int(packet.udp.srcport)] += 1
                        stats["dst_ports"][int(packet.udp.dstport)] += 1
                except (AttributeError, ValueError):
                    pass
        
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
        if not self.capture:
            self.load_capture()
        if self.capture is None:
            raise RuntimeError("Capture is not loaded; cannot extract conversations.")
        
        # Reload capture for second pass
        self.capture.close()
        self.capture = pyshark.FileCapture(self.pcap_file_path, keep_packets=False)
        
        conversations = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "start_time": None,
            "end_time": None,
            "protocols": set()
        })
        
        try:
            for packet in self.capture:
                # Get timestamp safely
                try:
                    if hasattr(packet, 'sniff_time'):
                        timestamp = packet.sniff_time.timestamp()
                    elif hasattr(packet, 'sniff_timestamp'):
                        timestamp = float(packet.sniff_timestamp)
                    else:
                        continue  # Skip packets without timestamps
                except (AttributeError, ValueError):
                    continue
                
                if hasattr(packet, 'ip'):
                    try:
                        # Create conversation key (sorted IPs for bidirectional flows)
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        conv_key = f"{min(src_ip, dst_ip)} <-> {max(src_ip, dst_ip)}"
                        
                        conv = conversations[conv_key]
                        conv["packets"] += 1
                        
                        # Get packet size safely
                        try:
                            conv["bytes"] += int(packet.length)
                        except (AttributeError, ValueError):
                            pass
                        
                        # Add protocol
                        if hasattr(packet, 'highest_layer') and packet.highest_layer:
                            conv["protocols"].add(packet.highest_layer)
                        
                        # Update time range
                        if conv["start_time"] is None:
                            conv["start_time"] = timestamp
                            conv["end_time"] = timestamp
                        else:
                            conv["start_time"] = min(conv["start_time"], timestamp)
                            conv["end_time"] = max(conv["end_time"], timestamp)
                            
                    except AttributeError:
                        continue  # Skip packets without proper IP info
        
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
        if not self.capture:
            self.load_capture()
        if self.capture is None:
            raise RuntimeError("Capture is not loaded; cannot analyze suspicious activity.")
        
        # Reload capture for third pass
        self.capture.close()
        self.capture = pyshark.FileCapture(self.pcap_file_path, keep_packets=False)
        
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
            for packet in self.capture:
                # Get packet size safely
                try:
                    packet_size = int(packet.length)
                except (AttributeError, ValueError):
                    packet_size = 0
                
                # Large packets (> 1500 bytes)
                if packet_size > 1500:
                    try:
                        timestamp = packet.sniff_time.timestamp() if hasattr(packet, 'sniff_time') else float(packet.sniff_timestamp)
                    except (AttributeError, ValueError):
                        timestamp = 0
                    
                    suspicious["large_packets"].append({
                        "size": packet_size,
                        "timestamp": timestamp,
                        "src": getattr(packet.ip, 'src', 'Unknown') if hasattr(packet, 'ip') else 'Unknown',
                        "dst": getattr(packet.ip, 'dst', 'Unknown') if hasattr(packet, 'ip') else 'Unknown'
                    })
                
                # Protocol analysis
                try:
                    protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else 'Unknown'
                    protocol_counts[protocol] += 1
                except AttributeError:
                    protocol_counts['Unknown'] += 1
                
                # IP packet counting and port scan detection
                if hasattr(packet, 'ip'):
                    try:
                        src_ip = packet.ip.src
                        ip_packet_counts[src_ip] += 1
                        
                        # Port scan detection
                        dst_port = None
                        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
                            dst_port = int(packet.tcp.dstport)
                        elif hasattr(packet, 'udp') and hasattr(packet.udp, 'dstport'):
                            dst_port = int(packet.udp.dstport)
                        
                        if dst_port:
                            ip_port_attempts[src_ip].add(dst_port)
                    except (AttributeError, ValueError):
                        pass
        
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
    
    def close(self):
        """Close the capture file"""
        if self.capture:
            try:
                self.capture.close()
            except Exception:
                pass  # Ignore errors when closing

async def pysharkAnalysis(pcap_file_path: str) -> Dict[str, Any]:
    """Analyze PCAP file using PyShark"""
    def _analyze():
        analyzer = PCAPAnalyzer(pcap_file_path)
        try:
            basic_stats = analyzer.get_basic_stats()
            conversations = analyzer.get_conversations()
            suspicious = analyzer.get_suspicious_activity()
            
            return {
                "basic_stats": basic_stats,
                "conversations": conversations,
                "suspicious_activity": suspicious
            }
        finally:
            analyzer.close()
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, _analyze)