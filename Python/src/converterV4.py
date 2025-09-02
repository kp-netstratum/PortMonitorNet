#!/usr/bin/env python3
"""
Complete PCAP to JSON Analyzer
Combines comprehensive frame analysis with network statistics and security analysis
Extracts all detailed information from PCAP files and outputs as structured JSON
"""

from scapy.all import rdpcap, IP, UDP, TCP, Ether, ICMP, DNS, ARP, Raw
import json
# import datetime
from datetime import datetime
import struct
import binascii
from collections import defaultdict, Counter
from typing import Dict, List, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=4)

class CompletePCAPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = None
        self.analysis_data = {
            'pcap_info': {},
            'frames': [],
            'basic_stats': {},
            'conversations': [],
            'tcp_streams': [],
            'suspicious_activity': {},
            'packet_table': [],
            'statistics': {}
        }
    
    def serialize_value(self, value):
        """Convert Scapy objects to JSON-serializable types"""
        if hasattr(value, 'real'):  # EDecimal has a 'real' attribute
            return float(value)
        elif hasattr(value, '__int__'):
            try:
                return int(value)
            except (ValueError, TypeError):
                return str(value)
        elif hasattr(value, '__float__'):
            try:
                return float(value)
            except (ValueError, TypeError):
                return str(value)
        elif hasattr(value, 'value'):  # FlagValue objects
            return int(value.value) if hasattr(value.value, '__int__') else str(value.value)
        else:
            return value
    
    def load_pcap(self):
        """Load PCAP file and basic information"""
        try:
            self.packets = rdpcap(self.pcap_file)
            self.analysis_data['pcap_info'] = {
                'filename': self.pcap_file,
                'total_packets': len(self.packets),
                'analysis_timestamp': datetime.now().isoformat()
            }
            return True
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            return False
    
    def get_timing_info(self, packet_index):
        """Calculate timing information for a packet"""
        timing_info = {
            'frame_number': packet_index + 1,
            'absolute_time': None,
            'epoch_time': None,
            'time_delta_previous': None,
            'time_since_first': None
        }
        
        current_packet = self.packets[packet_index]
        
        if hasattr(current_packet, 'time'):
            currentTime = float(self.serialize_value(current_packet.time))
            timing_info['absolute_time'] = datetime.fromtimestamp(currentTime).isoformat()
            timing_info['epoch_time'] = currentTime
            
            # Time delta from previous frame
            if packet_index > 0:
                prev_packet = self.packets[packet_index - 1]
                if hasattr(prev_packet, 'time'):
                    prev_time = float(self.serialize_value(prev_packet.time))
                    timing_info['time_delta_previous'] = currentTime - prev_time
            
            # Time since first frame
            if packet_index > 0:
                first_packet = self.packets[0]
                if hasattr(first_packet, 'time'):
                    first_time = float(self.serialize_value(first_packet.time))
                    timing_info['time_since_first'] = currentTime - first_time
        
        return timing_info
    
    def analyze_ethernet_layer(self, packet):
        """Extract Ethernet layer information"""
        if not packet.haslayer(Ether):
            return None
        
        eth = packet[Ether]
        
        # Extract OUI (Organizationally Unique Identifier)
        src_oui = eth.src.replace(':', '')[:6].upper()
        dst_oui = eth.dst.replace(':', '')[:6].upper()
        
        # Analyze MAC address bits
        dst_bytes = bytes.fromhex(eth.dst.replace(':', ''))
        src_bytes = bytes.fromhex(eth.src.replace(':', ''))
        
        return {
            'source_mac': str(eth.src),
            'destination_mac': str(eth.dst),
            'source_oui': src_oui,
            'destination_oui': dst_oui,
            'ethertype': hex(int(self.serialize_value(eth.type))),
            'ethertype_decimal': int(self.serialize_value(eth.type)),
            'destination_lg_bit': bool(dst_bytes[0] & 0x02),  # Local/Global bit
            'destination_ig_bit': bool(dst_bytes[0] & 0x01),  # Individual/Group bit
            'source_lg_bit': bool(src_bytes[0] & 0x02),
            'source_ig_bit': bool(src_bytes[0] & 0x01),
            'frame_type': 'Ethernet II'
        }
    
    def analyze_arp_layer(self, packet):
        """Extract ARP layer information"""
        if not packet.haslayer(ARP):
            return None
        
        arp = packet[ARP]
        
        return {
            'hardware_type': int(self.serialize_value(arp.hwtype)),
            'protocol_type': hex(int(self.serialize_value(arp.ptype))),
            'hardware_length': int(self.serialize_value(arp.hwlen)),
            'protocol_length': int(self.serialize_value(arp.plen)),
            'operation': int(self.serialize_value(arp.op)),
            'operation_name': 'Request' if int(self.serialize_value(arp.op)) == 1 else 'Reply' if int(self.serialize_value(arp.op)) == 2 else 'Unknown',
            'sender_mac': str(arp.hwsrc),
            'sender_ip': str(arp.psrc),
            'target_mac': str(arp.hwdst),
            'target_ip': str(arp.pdst)
        }
    
    def analyze_ip_layer(self, packet):
        """Extract IP layer information"""
        if not packet.haslayer(IP):
            return None
        
        ip = packet[IP]
        
        # Analyze flags - handle both FlagValue and int types
        try:
            flags_val = int(self.serialize_value(ip.flags))
        except (ValueError, AttributeError, TypeError):
            flags_val = 0
        
        flags_detail = {
            'reserved': bool(flags_val & 4),
            'dont_fragment': bool(flags_val & 2),
            'more_fragments': bool(flags_val & 1)
        }
        
        # DSCP and ECN analysis
        tos_val = int(self.serialize_value(ip.tos))
        dscp = (tos_val >> 2) & 0x3F
        ecn = tos_val & 0x03
        
        return {
            'version': int(self.serialize_value(ip.version)),
            'header_length_bytes': int(self.serialize_value(ip.ihl)) * 4,
            'header_length_words': int(self.serialize_value(ip.ihl)),
            'type_of_service': hex(tos_val),
            'dscp': dscp,
            'ecn': ecn,
            'dscp_name': self.get_dscp_name(dscp),
            'ecn_name': self.get_ecn_name(ecn),
            'total_length': int(self.serialize_value(ip.len)),
            'identification': hex(int(self.serialize_value(ip.id))),
            'identification_decimal': int(self.serialize_value(ip.id)),
            'flags': hex(flags_val),
            'flags_detail': flags_detail,
            'fragment_offset': int(self.serialize_value(ip.frag)),
            'ttl': int(self.serialize_value(ip.ttl)),
            'protocol': int(self.serialize_value(ip.proto)),
            'protocol_name': self.get_protocol_name(int(self.serialize_value(ip.proto))),
            'header_checksum': hex(int(self.serialize_value(ip.chksum))),
            'source_address': str(ip.src),
            'destination_address': str(ip.dst)
        }
    
    def analyze_tcp_layer(self, packet):
        """Extract TCP layer information"""
        if not packet.haslayer(TCP):
            return None
        
        tcp = packet[TCP]
        
        # Analyze TCP flags - handle both FlagValue and int types
        try:
            flags_val = int(self.serialize_value(tcp.flags))
        except (ValueError, AttributeError, TypeError):
            flags_val = 0
        
        flags_detail = {
            'fin': bool(flags_val & 0x001),
            'syn': bool(flags_val & 0x002),
            'rst': bool(flags_val & 0x004),
            'psh': bool(flags_val & 0x008),
            'ack': bool(flags_val & 0x010),
            'urg': bool(flags_val & 0x020),
            'ece': bool(flags_val & 0x040),
            'cwr': bool(flags_val & 0x080)
        }
        
        # TCP options analysis
        options_detail = self.analyze_tcp_options(tcp)
        
        # Calculate payload length
        payload_length = len(tcp.payload) if tcp.payload else 0
        
        return {
            'source_port': int(self.serialize_value(tcp.sport)),
            'destination_port': int(self.serialize_value(tcp.dport)),
            'sequence_number': int(self.serialize_value(tcp.seq)),
            'acknowledgment_number': int(self.serialize_value(tcp.ack)),
            'header_length_bytes': int(self.serialize_value(tcp.dataofs)) * 4,
            'header_length_words': int(self.serialize_value(tcp.dataofs)),
            'flags': hex(flags_val),
            'flags_decimal': flags_val,
            'flags_detail': flags_detail,
            'window_size': int(self.serialize_value(tcp.window)),
            'checksum': hex(int(self.serialize_value(tcp.chksum))),
            'urgent_pointer': int(self.serialize_value(tcp.urgptr)),
            'options': options_detail,
            'payload_length': payload_length,
            'has_payload': payload_length > 0
        }
    
    def analyze_udp_layer(self, packet):
        """Extract UDP layer information"""
        if not packet.haslayer(UDP):
            return None
        
        udp = packet[UDP]
        payload_length = len(udp.payload) if udp.payload else 0
        
        return {
            'source_port': int(self.serialize_value(udp.sport)),
            'destination_port': int(self.serialize_value(udp.dport)),
            'length': int(self.serialize_value(udp.len)),
            'checksum': hex(int(self.serialize_value(udp.chksum))),
            'payload_length': payload_length,
            'has_payload': payload_length > 0
        }
    
    def analyze_icmp_layer(self, packet):
        """Extract ICMP layer information"""
        if not packet.haslayer(ICMP):
            return None
        
        icmp = packet[ICMP]
        icmp_data = {
            'type': int(self.serialize_value(icmp.type)),
            'code': int(self.serialize_value(icmp.code)),
            'checksum': hex(int(self.serialize_value(icmp.chksum))),
            'type_name': self.get_icmp_type_name(int(self.serialize_value(icmp.type)))
        }
        
        # Add optional fields if they exist
        if hasattr(icmp, 'id'):
            icmp_data['id'] = int(self.serialize_value(icmp.id))
        if hasattr(icmp, 'seq'):
            icmp_data['sequence'] = int(self.serialize_value(icmp.seq))
        
        return icmp_data
    
    def analyze_dns_layer(self, packet):
        """Extract DNS layer information"""
        if not packet.haslayer(DNS):
            return None
        
        dns = packet[DNS]
        
        dns_data = {
            'transaction_id': hex(int(self.serialize_value(dns.id))),
            'query_response': 'Response' if int(self.serialize_value(dns.qr)) == 1 else 'Query',
            'opcode': int(self.serialize_value(dns.opcode)),
            'authoritative': bool(int(self.serialize_value(dns.aa))),
            'truncated': bool(int(self.serialize_value(dns.tc))),
            'recursion_desired': bool(int(self.serialize_value(dns.rd))),
            'recursion_available': bool(int(self.serialize_value(dns.ra))),
            'response_code': int(self.serialize_value(dns.rcode)),
            'questions': int(self.serialize_value(dns.qdcount)),
            'answer_rrs': int(self.serialize_value(dns.ancount)),
            'authority_rrs': int(self.serialize_value(dns.nscount)),
            'additional_rrs': int(self.serialize_value(dns.arcount))
        }
        
        # Extract query information
        if dns.qd and int(self.serialize_value(dns.qr)) == 0:  # Query
            try:
                query_name = dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
                dns_data['query_name'] = query_name
                dns_data['query_type'] = int(self.serialize_value(dns.qd.qtype))
                dns_data['query_class'] = int(self.serialize_value(dns.qd.qclass))
            except:
                pass
        
        return dns_data
    
    def analyze_application_layer(self, packet):
        """Analyze application layer protocols"""
        app_data = {}
        
        # HTTP detection
        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load
                if isinstance(raw_data, bytes):
                    data_str = raw_data.decode('utf-8', errors='ignore')
                else:
                    data_str = str(raw_data)
                
                # Check for HTTP
                if any(keyword in data_str for keyword in ['HTTP/', 'GET ', 'POST ', 'PUT ', 'DELETE ']):
                    lines = data_str.split('\r\n')
                    if lines:
                        app_data['http'] = {
                            'first_line': lines[0],
                            'is_request': any(method in lines[0] for method in ['GET', 'POST', 'PUT', 'DELETE']),
                            'data_length': len(raw_data)
                        }
                        
                        # Extract headers
                        headers = {}
                        for line in lines[1:]:
                            if ':' in line and line.strip():
                                key, value = line.split(':', 1)
                                headers[key.strip()] = value.strip()
                        app_data['http']['headers'] = headers
            except:
                pass
        
        # DNS analysis
        dns_info = self.analyze_dns_layer(packet)
        if dns_info:
            app_data['dns'] = dns_info
        
        return app_data if app_data else None
    
    def analyze_tcp_options(self, tcp_layer):
        """Analyze TCP options in detail"""
        options_detail = []
        
        if not tcp_layer.options:
            return options_detail
        
        for option in tcp_layer.options:
            if isinstance(option, tuple):
                opt_kind = option[0]
                opt_data = option[1] if len(option) > 1 else None
                
                if opt_kind == 'NOP':
                    options_detail.append({
                        'type': 'NOP',
                        'description': 'No Operation',
                        'length': 1
                    })
                elif opt_kind == 'Timestamp':
                    if opt_data and len(opt_data) >= 8:
                        tsval = struct.unpack('>I', opt_data[:4])[0]
                        tsecr = struct.unpack('>I', opt_data[4:8])[0]
                        options_detail.append({
                            'type': 'Timestamp',
                            'length': 10,
                            'tsval': tsval,
                            'tsecr': tsecr,
                            'description': f'Timestamps: TSval {tsval}, TSecr {tsecr}'
                        })
                elif opt_kind == 'MSS':
                    mss_val = int(self.serialize_value(opt_data)) if opt_data else 0
                    options_detail.append({
                        'type': 'MSS',
                        'length': 4,
                        'value': mss_val,
                        'description': f'Maximum Segment Size: {mss_val}'
                    })
                elif opt_kind == 'WScale':
                    wscale_val = int(self.serialize_value(opt_data)) if opt_data else 0
                    options_detail.append({
                        'type': 'WScale',
                        'length': 3,
                        'value': wscale_val,
                        'description': f'Window Scale: {wscale_val}'
                    })
                elif opt_kind == 'SAckOK':
                    options_detail.append({
                        'type': 'SAckOK',
                        'length': 2,
                        'description': 'SACK Permitted'
                    })
                else:
                    options_detail.append({
                        'type': str(opt_kind),
                        'data': str(opt_data) if opt_data else None,
                        'description': f'Option: {opt_kind}'
                    })
        
        return options_detail
    
    def get_protocol_hierarchy(self, packet):
        """Get the protocol hierarchy for the packet"""
        protocols = []
        
        if packet.haslayer(Ether):
            protocols.append('eth')
            eth_type = int(self.serialize_value(packet[Ether].type))
            if eth_type == 0x0800:  # IPv4
                protocols.append('ethertype')
            elif eth_type == 0x0806:  # ARP
                protocols.append('arp')
        
        if packet.haslayer(ARP):
            protocols.append('arp')
        elif packet.haslayer(IP):
            protocols.append('ip')
            
            if packet.haslayer(TCP):
                protocols.append('tcp')
                # Check for HTTP
                if packet.haslayer(Raw):
                    try:
                        raw_data = packet[Raw].load
                        data_str = raw_data.decode('utf-8', errors='ignore') if isinstance(raw_data, bytes) else str(raw_data)
                        if any(keyword in data_str for keyword in ['HTTP/', 'GET ', 'POST ']):
                            protocols.append('http')
                    except:
                        pass
            elif packet.haslayer(UDP):
                protocols.append('udp')
                if packet.haslayer(DNS):
                    protocols.append('dns')
            elif packet.haslayer(ICMP):
                protocols.append('icmp')
        
        return protocols[-1]
    
    def get_raw_data(self, packet, max_bytes=None):
        """Get raw packet data as hex string"""
        raw_data = bytes(packet)
        if max_bytes:
            raw_data = raw_data[:max_bytes]
        
        return {
            'hex_string': raw_data.hex(),
            'hex_formatted': ' '.join([f'{b:02x}' for b in raw_data]),
            'ascii': ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_data]),
            'length': len(raw_data)
        }
        
    def format_info_column(self, pkt):
        src, dst, info = None, None, None

        # --- ARP ---
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            src, dst = arp.hwsrc, arp.hwdst
            if arp.op == 1:  # who-has
                info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:  # is-at
                info = f"{arp.psrc} is at {arp.hwsrc}"
            return src, dst, info

        # --- TCP ---
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip, tcp = pkt[IP], pkt[TCP]
            src, dst = ip.src, ip.dst
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x20: flags.append("URG")

            info = f"{tcp.sport} → {tcp.dport}"
            if flags:
                info += f" [{', '.join(flags)}]"
            info += f" Seq={tcp.seq} Win={tcp.window} Len={len(tcp.payload)}"
            if tcp.flags & 0x10:
                info += f" Ack={tcp.ack}"

            opts = []
            for opt in tcp.options:
                if opt[0] == "MSS":
                    opts.append(f"MSS={opt[1]}")
                elif opt[0] == "WScale":
                    opts.append(f"WS={opt[1]}")
                elif opt[0] == "Timestamp":
                    tsval, tsecr = opt[1]
                    opts.append(f"TSval={tsval} TSecr={tsecr}")
                elif opt[0] == "SAckOK":
                    opts.append("SACK_PERM")
            if opts:
                info += " " + " ".join(opts)

            return src, dst, info

        # --- UDP ---
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            ip, udp = pkt[IP], pkt[UDP]
            src, dst = ip.src, ip.dst
            info = f"{udp.sport} → {udp.dport} Len={len(udp.payload)}"
            return src, dst, info

        # --- ICMP ---
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            ip, icmp = pkt[IP], pkt[ICMP]
            src, dst = ip.src, ip.dst
            info = f"ICMP type={icmp.type} code={icmp.code}"
            return src, dst, info

        # --- Fallback (Ethernet only) ---
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            src, dst = eth.src, eth.dst
            info = "Ethernet frame"
            return src, dst, info

        return None, None, "Unknown packet"

    
    def analyze_single_frame(self, packet_index):
        """Analyze a single frame and return structured data"""
        packet = self.packets[packet_index]
        src, dst, info = self.format_info_column(packet)

        frame_data = {
            'frame_info': {
                'frame_number': packet_index + 1,
                'frame_length_bytes': len(packet),
                'frame_length_bits': len(packet) * 8,
                'capture_length_bytes': len(packet),
                'capture_length_bits': len(packet) * 8,
                'protocols_in_frame': self.get_protocol_hierarchy(packet),
                'info': info,
                'src': src,
                'dst': dst,
            }
        }

        # tcp_info = self.format_tcp_info(packet, frame_no=packet_index + 1)
        # print(tcp_info)
        # if tcp_info:
        #     frame_data['frame_info']['info_column'] = tcp_info
        
        # Add timing information
        frame_data['timing'] = self.get_timing_info(packet_index)
        
        # Analyze each layer
        ethernet_info = self.analyze_ethernet_layer(packet)
        if ethernet_info:
            frame_data['ethernet'] = ethernet_info
        
        arp_info = self.analyze_arp_layer(packet)
        if arp_info:
            frame_data['arp'] = arp_info
        
        ip_info = self.analyze_ip_layer(packet)
        if ip_info:
            frame_data['ip'] = ip_info
        
        tcp_info = self.analyze_tcp_layer(packet)
        if tcp_info:
            frame_data['tcp'] = tcp_info
        
        udp_info = self.analyze_udp_layer(packet)
        if udp_info:
            frame_data['udp'] = udp_info
        
        icmp_info = self.analyze_icmp_layer(packet)
        if icmp_info:
            frame_data['icmp'] = icmp_info
        
        # Application layer analysis
        app_info = self.analyze_application_layer(packet)
        if app_info:
            frame_data['application'] = app_info
        
        # Add raw data (first 256 bytes)
        frame_data['raw_data'] = self.get_raw_data(packet, max_bytes=256)
        
        return frame_data
    
    def analyze_all_frames(self):
        """Analyze all frames in the PCAP file"""
        if not self.packets:
            if not self.load_pcap():
                return None
        
        print(f"Analyzing {len(self.packets)} frames...")
        
        for i in range(len(self.packets)):
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1}/{len(self.packets)} frames...")
            
            try:
                frame_data = self.analyze_single_frame(i)
                self.analysis_data['frames'].append(frame_data)
            except Exception as e:
                print(f"Error analyzing frame {i + 1}: {e}")
                self.analysis_data['frames'].append({
                    'frame_info': {
                        'frame_number': i + 1,
                        'frame_length_bytes': len(self.packets[i]),
                        'error': str(e)
                    }
                })
        
        print(f"Analysis complete. Processed {len(self.packets)} frames.")
        return self.analysis_data
    
    def get_basic_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the PCAP file"""
        if not self.packets:
            self.load_pcap()
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
                except (AttributeError, ValueError, TypeError):
                    pass
                
                # Protocol analysis
                if packet.haslayer(TCP):
                    stats["protocols"]["TCP"] += 1
                elif packet.haslayer(UDP):
                    stats["protocols"]["UDP"] += 1
                elif packet.haslayer(ARP):
                    stats["protocols"]["ARP"] += 1
                elif packet.haslayer(ICMP):
                    stats["protocols"]["ICMP"] += 1
                elif packet.haslayer(IP):
                    stats["protocols"]["IP"] += 1
                else:
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
            self.load_pcap()
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
                    
                    try:
                        timestamp = float(packet.time)
                    except (AttributeError, ValueError, TypeError):
                        continue
                    
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
                    elif packet.haslayer(ICMP):
                        conv["protocols"].add("ICMP")
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
        
        result.sort(key=lambda x: x["packets"], reverse=True)
        return result[:20]
    
    def get_tcp_streams(self):
        """Identify and group TCP streams"""
        streams = {}
        stream_id = 0
        
        for i, packet in enumerate(self.packets):
            if packet.haslayer(TCP) and packet.haslayer(IP):
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                
                # Create stream identifier
                sport = int(self.serialize_value(tcp_layer.sport))
                dport = int(self.serialize_value(tcp_layer.dport))
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                
                stream_key1 = f"{src_ip}:{sport}-{dst_ip}:{dport}"
                stream_key2 = f"{dst_ip}:{dport}-{src_ip}:{sport}"
                
                # Check if stream already exists
                found_stream = None
                for stream_k, stream_data in streams.items():
                    if stream_key1 in stream_data['identifiers'] or stream_key2 in stream_data['identifiers']:
                        found_stream = stream_k
                        break
                
                if found_stream is None:
                    # New stream
                    streams[stream_id] = {
                        'stream_id': stream_id,
                        'identifiers': [stream_key1, stream_key2],
                        'packets': [i + 1],
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': sport,
                        'dst_port': dport
                    }
                    stream_id += 1
                else:
                    # Add to existing stream
                    streams[found_stream]['packets'].append(i + 1)
        
        return list(streams.values())
    
    def get_suspicious_activity(self) -> Dict[str, Any]:
        """Identify potentially suspicious network activity"""
        if not self.packets:
            self.load_pcap()
        if self.packets is None:
            raise RuntimeError("Capture is not loaded; cannot analyze suspicious activity.")
        
        suspicious = {
            "port_scans": [],
            "large_packets": [],
            "unusual_protocols": [],
            "high_volume_ips": [],
            "failed_connections": []
        }
        
        ip_port_attempts = defaultdict(set)
        protocol_counts = Counter()
        ip_packet_counts = Counter()
        failed_connections = defaultdict(int)
        
        try:
            for packet in self.packets:
                packet_size = len(packet)
                
                # Large packets (> 1500 bytes)
                if packet_size > 1500:
                    try:
                        timestamp = float(packet.time)
                    except (AttributeError, ValueError, TypeError):
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
                    # Check for failed connections (RST flags)
                    tcp = packet[TCP]
                    if hasattr(tcp, 'flags'):
                        flags_val = int(self.serialize_value(tcp.flags))
                        if flags_val & 0x004:  # RST flag
                            if packet.haslayer(IP):
                                conn_key = f"{packet[IP].src}:{tcp.sport}-{packet[IP].dst}:{tcp.dport}"
                                failed_connections[conn_key] += 1
                elif packet.haslayer(UDP):
                    protocol_counts["UDP"] += 1
                elif packet.haslayer(ARP):
                    protocol_counts["ARP"] += 1
                elif packet.haslayer(ICMP):
                    protocol_counts["ICMP"] += 1
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
            if len(ports) > 10:
                suspicious["port_scans"].append({
                    "src_ip": ip,
                    "ports_accessed": len(ports),
                    "ports": sorted(list(ports))[:20]
                })
        
        # High volume IPs
        total_packets = sum(ip_packet_counts.values())
        if total_packets > 0:
            for ip, count in ip_packet_counts.most_common(5):
                if count > total_packets * 0.1:
                    suspicious["high_volume_ips"].append({
                        "ip": ip,
                        "packet_count": count,
                        "percentage": round((count / total_packets) * 100, 2)
                    })
        
        # Unusual protocols (low frequency)
        total_protocol_packets = sum(protocol_counts.values())
        if total_protocol_packets > 0:
            for protocol, count in protocol_counts.items():
                if count < total_protocol_packets * 0.01 and count > 0:
                    suspicious["unusual_protocols"].append({
                        "protocol": protocol,
                        "count": count,
                        "percentage": round((count / total_protocol_packets) * 100, 2)
                    })
        
        # Failed connections
        for conn_key, count in failed_connections.items():
            if count > 5:  # More than 5 RST packets for same connection
                suspicious["failed_connections"].append({
                    "connection": conn_key,
                    "rst_count": count
                })
        
        return suspicious
    
    def get_packet_table_rows(self, max_rows: int = None) -> List[Dict[str, Any]]:
        """Build Wireshark-style packet table"""
        if not self.packets:
            self.load_pcap()
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
                # Time calculations
                try:
                    pkt_time = float(packet.time)
                    if first_time is not None:
                        rel_time = round(pkt_time - first_time, 6)
                    else:
                        rel_time = round(pkt_time, 6)
                    timestamp_str = datetime.fromtimestamp(pkt_time).isoformat()
                except Exception:
                    rel_time = 0.0
                    timestamp_str = ""

                # Protocol determination and info generation
                protocol_name = "Unknown"
                info_parts = []
                src_addr = "-"
                dst_addr = "-"
                
                # Handle different protocol layers
                if packet.haslayer(ARP):
                    protocol_name = "ARP"
                    arp = packet[ARP]
                    src_addr = f"{arp.hwsrc} ({arp.psrc})"
                    dst_addr = f"{arp.hwdst} ({arp.pdst})"
                    if int(self.serialize_value(arp.op)) == 1:
                        info_parts.append(f"Who has {arp.pdst}? Tell {arp.psrc}")
                    elif int(self.serialize_value(arp.op)) == 2:
                        info_parts.append(f"{arp.psrc} is at {arp.hwsrc}")
                
                elif packet.haslayer(IP):
                    ip = packet[IP]
                    src_addr = str(ip.src)
                    dst_addr = str(ip.dst)
                    
                    if packet.haslayer(TCP):
                        protocol_name = "TCP"
                        tcp = packet[TCP]
                        sport = int(self.serialize_value(tcp.sport))
                        dport = int(self.serialize_value(tcp.dport))
                        flags = tcp.flags
                        seq = int(self.serialize_value(tcp.seq))
                        ack = int(self.serialize_value(tcp.ack))
                        
                        src_addr = f"{src_addr}:{sport}"
                        dst_addr = f"{dst_addr}:{dport}"
                        
                        # Check for HTTP
                        if packet.haslayer(Raw):
                            try:
                                raw_data = packet[Raw].load
                                data_str = raw_data.decode('utf-8', errors='ignore') if isinstance(raw_data, bytes) else str(raw_data)
                                if any(keyword in data_str for keyword in ['HTTP/', 'GET ', 'POST ', 'PUT ', 'DELETE ']):
                                    protocol_name = "HTTP"
                                    lines = data_str.split('\r\n')
                                    if lines:
                                        info_parts.append(lines[0])
                            except:
                                pass
                        
                        if not info_parts:  # If no HTTP detected
                            flag_names = []
                            flags_val = int(self.serialize_value(flags))
                            if flags_val & 0x002: flag_names.append('SYN')
                            if flags_val & 0x010: flag_names.append('ACK')
                            if flags_val & 0x001: flag_names.append('FIN')
                            if flags_val & 0x004: flag_names.append('RST')
                            if flags_val & 0x008: flag_names.append('PSH')
                            if flags_val & 0x020: flag_names.append('URG')
                            
                            info_parts.append(f"[{', '.join(flag_names)}] Seq={seq} Ack={ack}")
                    
                    elif packet.haslayer(UDP):
                        protocol_name = "UDP"
                        udp = packet[UDP]
                        sport = int(self.serialize_value(udp.sport))
                        dport = int(self.serialize_value(udp.dport))
                        
                        src_addr = f"{src_addr}:{sport}"
                        dst_addr = f"{dst_addr}:{dport}"
                        
                        if packet.haslayer(DNS):
                            protocol_name = "DNS"
                            dns = packet[DNS]
                            if int(self.serialize_value(dns.qr)) == 0:  # Query
                                if dns.qd:
                                    query_name = dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
                                    info_parts.append(f"Standard query {query_name}")
                            else:  # Response
                                info_parts.append("Standard query response")
                        else:
                            info_parts.append(f"Length={int(self.serialize_value(udp.len))}")
                    
                    elif packet.haslayer(ICMP):
                        protocol_name = "ICMP"
                        icmp = packet[ICMP]
                        icmp_type = int(self.serialize_value(icmp.type))
                        icmp_code = int(self.serialize_value(icmp.code))
                        info_parts.append(f"Type={icmp_type} Code={icmp_code}")
                    
                    else:
                        protocol_name = "IP"
                        info_parts.append(f"Protocol={int(self.serialize_value(ip.proto))}")
                
                else:
                    try:
                        protocol_name = packet.lastlayer().__class__.__name__
                        info_parts.append(packet.summary())
                    except Exception:
                        info_parts.append("Unknown packet")

                info_value = "; ".join([p for p in info_parts if p]) if info_parts else "No info"

                rows.append({
                    "no": index,
                    "time": rel_time,
                    "timestamp": timestamp_str,
                    "source": src_addr,
                    "destination": dst_addr,
                    "protocol": protocol_name,
                    "length": len(packet),
                    "info": info_value,
                })

                if max_rows is not None and len(rows) >= max_rows:
                    break

        except Exception as e:
            raise RuntimeError(f"Error building packet table: {str(e)}")

        return rows
    
    def generate_statistics(self):
        """Generate comprehensive statistics"""
        stats = {
            'total_frames': len(self.analysis_data['frames']),
            'protocol_distribution': {},
            'size_distribution': {
                'min_frame_size': float('inf'),
                'max_frame_size': 0,
                'avg_frame_size': 0,
                'total_bytes': 0
            },
            'ip_addresses': set(),
            'mac_addresses': set(),
            'ports': set(),
            'unique_conversations': 0,
            'unique_tcp_streams': 0
        }
        
        total_size = 0
        
        for frame in self.analysis_data['frames']:
            # Skip frames with errors
            if 'error' in frame.get('frame_info', {}):
                continue
                
            # Protocol distribution
            protocols = frame['frame_info'].get('protocols_in_frame', [])
            for protocol in protocols:
                stats['protocol_distribution'][protocol] = stats['protocol_distribution'].get(protocol, 0) + 1
            
            # Size statistics
            frame_size = frame['frame_info']['frame_length_bytes']
            total_size += frame_size
            stats['size_distribution']['min_frame_size'] = min(stats['size_distribution']['min_frame_size'], frame_size)
            stats['size_distribution']['max_frame_size'] = max(stats['size_distribution']['max_frame_size'], frame_size)
            
            # Collect addresses and ports
            if 'ip' in frame:
                stats['ip_addresses'].add(frame['ip']['source_address'])
                stats['ip_addresses'].add(frame['ip']['destination_address'])
            
            if 'ethernet' in frame:
                stats['mac_addresses'].add(frame['ethernet']['source_mac'])
                stats['mac_addresses'].add(frame['ethernet']['destination_mac'])
            
            if 'tcp' in frame:
                stats['ports'].add(frame['tcp']['source_port'])
                stats['ports'].add(frame['tcp']['destination_port'])
            
            if 'udp' in frame:
                stats['ports'].add(frame['udp']['source_port'])
                stats['ports'].add(frame['udp']['destination_port'])
        
        # Finalize statistics
        stats['size_distribution']['total_bytes'] = total_size
        if stats['size_distribution']['min_frame_size'] == float('inf'):
            stats['size_distribution']['min_frame_size'] = 0
        stats['size_distribution']['avg_frame_size'] = total_size / len(self.analysis_data['frames']) if self.analysis_data['frames'] else 0
        
        # Convert sets to lists for JSON serialization
        stats['ip_addresses'] = list(stats['ip_addresses'])
        stats['mac_addresses'] = list(stats['mac_addresses'])
        stats['ports'] = sorted(list(stats['ports']))
        
        # Add conversation and stream counts
        stats['unique_conversations'] = len(self.analysis_data.get('conversations', []))
        stats['unique_tcp_streams'] = len(self.analysis_data.get('tcp_streams', []))
        
        return stats
    
    def add_stream_analysis(self):
        """Add TCP stream analysis to the data"""
        tcp_streams = self.get_tcp_streams()
        self.analysis_data['tcp_streams'] = tcp_streams
        
        # Add stream index to each frame
        for stream in tcp_streams:
            for packet_num in stream['packets']:
                frame_index = packet_num - 1
                if frame_index < len(self.analysis_data['frames']) and 'tcp' in self.analysis_data['frames'][frame_index]:
                    self.analysis_data['frames'][frame_index]['tcp']['stream_index'] = stream['stream_id']
    
    def get_dscp_name(self, dscp):
        """Get DSCP name from value"""
        dscp_names = {
            0: 'CS0 (Default)', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13',
            16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23', 24: 'CS3',
            26: 'AF31', 28: 'AF32', 30: 'AF33', 32: 'CS4', 34: 'AF41',
            36: 'AF42', 38: 'AF43', 40: 'CS5', 44: 'Voice Admit',
            46: 'EF (Expedited Forwarding)', 48: 'CS6', 56: 'CS7'
        }
        return dscp_names.get(dscp, f'Unknown ({dscp})')
    
    def get_ecn_name(self, ecn):
        """Get ECN name from value"""
        ecn_names = {0: 'Not-ECT', 1: 'ECT(1)', 2: 'ECT(0)', 3: 'CE'}
        return ecn_names.get(ecn, f'Unknown ({ecn})')
    
    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        protocol_names = {
            1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 
            41: 'IPv6', 58: 'ICMPv6', 89: 'OSPF'
        }
        return protocol_names.get(protocol_num, f'Unknown ({protocol_num})')
    
    def get_icmp_type_name(self, icmp_type):
        """Get ICMP type name from value"""
        icmp_types = {
            0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
            5: 'Redirect', 8: 'Echo Request', 11: 'Time Exceeded',
            12: 'Parameter Problem', 13: 'Timestamp Request', 14: 'Timestamp Reply'
        }
        return icmp_types.get(icmp_type, f'Unknown ({icmp_type})')
    
    def complete_analysis(self, include_raw_data=True, max_table_rows=1000):
        """Perform complete analysis combining both approaches"""
        if not self.load_pcap():
            return None
        
        print(f"Starting complete analysis of {len(self.packets)} packets...")
        
        # 1. Detailed frame analysis
        print("Analyzing individual frames...")
        self.analyze_all_frames()
        
        # 2. Basic statistics
        print("Computing basic statistics...")
        self.analysis_data['basic_stats'] = self.get_basic_stats()
        
        # 3. Conversation analysis
        print("Analyzing conversations...")
        self.analysis_data['conversations'] = self.get_conversations()
        
        # 4. TCP stream analysis
        print("Analyzing TCP streams...")
        self.add_stream_analysis()
        
        # 5. Security analysis
        print("Performing security analysis...")
        self.analysis_data['suspicious_activity'] = self.get_suspicious_activity()
        
        # 6. Packet table (Wireshark-style)
        print("Building packet table...")
        self.analysis_data['packet_table'] = self.get_packet_table_rows(max_rows=max_table_rows)
        
        # 7. Generate comprehensive statistics
        print("Generating statistics...")
        self.analysis_data['statistics'] = self.generate_statistics()
        
        # 8. Optionally remove raw data to reduce size
        if not include_raw_data:
            for frame in self.analysis_data['frames']:
                if 'raw_data' in frame:
                    del frame['raw_data']
        
        print("Analysis complete!")
        return self.analysis_data
    
    def export_json(self, output_file=None, pretty_print=True):
        """Export analysis data as JSON"""
        if not self.analysis_data['frames']:
            print("No data to export. Run complete_analysis() first.")
            return None
        
        # Ensure all data is JSON serializable
        json_data = self.ensure_json_serializable(self.analysis_data)
        
        json_output = json.dumps(
            json_data, 
            indent=2 if pretty_print else None,
            ensure_ascii=False
        )
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Analysis exported to {output_file}")
        
        return json_output
    
    def ensure_json_serializable(self, obj):
        """Recursively convert objects to JSON serializable types"""
        if isinstance(obj, dict):
            return {k: self.ensure_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.ensure_json_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        elif hasattr(obj, '__float__'):  # EDecimal and similar
            try:
                return float(obj)
            except (ValueError, TypeError):
                return str(obj)
        elif hasattr(obj, '__str__') and not isinstance(obj, (str, int, float, bool, type(None))):
            return str(obj)
        else:
            return obj

# Convenience functions
def analyze_pcap_complete(pcap_file, output_file=None, include_raw_data=True, max_table_rows=1000):
    """
    Complete PCAP analysis with all features
    
    Args:
        pcap_file (str): Path to PCAP file
        output_file (str): Optional output JSON file path
        include_raw_data (bool): Include raw packet data in output
        max_table_rows (int): Maximum rows in packet table
    
    Returns:
        dict: Complete analysis results
    """
    analyzer = CompletePCAPAnalyzer(pcap_file)
    analysis_data = analyzer.complete_analysis(include_raw_data, max_table_rows)
    
    if output_file:
        analyzer.export_json(output_file)
    
    return analysis_data

def get_frame_details(pcap_file, frame_number):
    """
    Get detailed information for a specific frame
    
    Args:
        pcap_file (str): Path to PCAP file
        frame_number (int): Frame number to analyze
    
    Returns:
        dict: Frame analysis data
    """
    analyzer = CompletePCAPAnalyzer(pcap_file)
    
    if not analyzer.load_pcap():
        return None
    
    if frame_number > len(analyzer.packets):
        print(f"Frame {frame_number} not found. Total frames: {len(analyzer.packets)}")
        return None
    
    return analyzer.analyze_single_frame(frame_number - 1)

def get_wireshark_table(pcap_file, max_rows=100):
    """
    Get Wireshark-style packet table
    
    Args:
        pcap_file (str): Path to PCAP file
        max_rows (int): Maximum number of rows to return
    
    Returns:
        list: Packet table data
    """
    analyzer = CompletePCAPAnalyzer(pcap_file)
    
    if not analyzer.load_pcap():
        return None
    
    return analyzer.get_packet_table_rows(max_rows=max_rows)

# Async wrapper
async def analyze_pcap_async(pcap_file: str, include_raw_data: bool = True, max_table_rows: int = 1000) -> Dict[str, Any]:
    """Async wrapper for complete PCAP analysis"""
    def _analyze():
        result = analyze_pcap_complete(pcap_file, None, include_raw_data, max_table_rows)
        return result
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, _analyze)