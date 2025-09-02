# #!/usr/bin/env python3
# """
# Complete PCAP to JSON Analyzer
# Extracts detailed information from all frames in a PCAP file and outputs as JSON
# """

# from scapy.all import rdpcap, IP, UDP, TCP, Ether, ICMP
# import json
# import datetime
# import struct

# class PCAPAnalyzer:
#     def __init__(self, pcap_file):
#         self.pcap_file = pcap_file
#         self.packets = None
#         self.analysis_data = {
#             'pcap_info': {},
#             'frames': []
#         }
    
#     def load_pcap(self):
#         """Load PCAP file and basic information"""
#         try:
#             self.packets = rdpcap(self.pcap_file)
#             self.analysis_data['pcap_info'] = {
#                 'filename': self.pcap_file,
#                 'total_packets': len(self.packets),
#                 'analysis_timestamp': datetime.datetime.now().isoformat()
#             }
#             return True
#         except Exception as e:
#             print(f"Error loading PCAP file: {e}")
#             return False
    
#     def get_timing_info(self, packet_index):
#         """Calculate timing information for a packet"""
#         timing_info = {
#             'frame_number': packet_index + 1,
#             'absolute_time': None,
#             'epoch_time': None,
#             'time_delta_previous': None,
#             'time_since_first': None
#         }
        
#         current_packet = self.packets[packet_index]
        
#         if hasattr(current_packet, 'time'):
#             currentTime = float(current_packet.time)
#             timing_info['absolute_time'] = datetime.datetime.fromtimestamp(currentTime).isoformat()
#             timing_info['epoch_time'] = currentTime
            
#             # Time delta from previous frame
#             if packet_index > 0:
#                 prev_packet = self.packets[packet_index - 1]
#                 if hasattr(prev_packet, 'time'):
#                     timing_info['time_delta_previous'] = currentTime - prev_packet.time
            
#             # Time since first frame
#             if packet_index > 0:
#                 first_packet = self.packets[0]
#                 if hasattr(first_packet, 'time'):
#                     timing_info['time_since_first'] = currentTime - first_packet.time
        
#         return timing_info
    
#     def analyze_ethernet_layer(self, packet):
#         """Extract Ethernet layer information"""
#         if not packet.haslayer(Ether):
#             return None
        
#         eth = packet[Ether]
        
#         # Extract OUI (Organizationally Unique Identifier)
#         src_oui = eth.src.replace(':', '')[:6].upper()
#         dst_oui = eth.dst.replace(':', '')[:6].upper()
        
#         # Analyze MAC address bits
#         dst_bytes = bytes.fromhex(eth.dst.replace(':', ''))
#         src_bytes = bytes.fromhex(eth.src.replace(':', ''))
        
#         return {
#             'source_mac': eth.src,
#             'destination_mac': eth.dst,
#             'source_oui': src_oui,
#             'destination_oui': dst_oui,
#             'ethertype': hex(eth.type),
#             'ethertype_decimal': eth.type,
#             'destination_lg_bit': bool(dst_bytes[0] & 0x02),  # Local/Global bit
#             'destination_ig_bit': bool(dst_bytes[0] & 0x01),  # Individual/Group bit
#             'source_lg_bit': bool(src_bytes[0] & 0x02),
#             'source_ig_bit': bool(src_bytes[0] & 0x01),
#             'frame_type': 'Ethernet II'
#         }
    
#     def analyze_ip_layer(self, packet):
#         """Extract IP layer information"""
#         if not packet.haslayer(IP):
#             return None
        
#         ip = packet[IP]
        
#         # Analyze flags - handle both FlagValue and int types
#         try:
#             # Convert flags to integer if it's a FlagValue object
#             if hasattr(ip.flags, 'value'):
#                 flags_val = int(ip.flags.value)
#             else:
#                 flags_val = int(ip.flags)
#         except (ValueError, AttributeError):
#             flags_val = 0
        
#         flags_detail = {
#             'reserved': bool(flags_val & 4),
#             'dont_fragment': bool(flags_val & 2),
#             'more_fragments': bool(flags_val & 1)
#         }
        
#         # DSCP and ECN analysis
#         dscp = (ip.tos >> 2) & 0x3F
#         ecn = ip.tos & 0x03
        
#         return {
#             'version': ip.version,
#             'header_length_bytes': ip.ihl * 4,
#             'header_length_words': ip.ihl,
#             'type_of_service': hex(ip.tos),
#             'dscp': dscp,
#             'ecn': ecn,
#             'dscp_name': self.get_dscp_name(dscp),
#             'ecn_name': self.get_ecn_name(ecn),
#             'total_length': ip.len,
#             'identification': hex(ip.id),
#             'identification_decimal': ip.id,
#             'flags': hex(flags_val),
#             'flags_detail': flags_detail,
#             'fragment_offset': ip.frag,
#             'ttl': ip.ttl,
#             'protocol': ip.proto,
#             'protocol_name': self.get_protocol_name(ip.proto),
#             'header_checksum': hex(ip.chksum),
#             'source_address': ip.src,
#             'destination_address': ip.dst
#         }
    
#     def analyze_tcp_layer(self, packet):
#         """Extract TCP layer information"""
#         if not packet.haslayer(TCP):
#             return None
        
#         tcp = packet[TCP]
        
#         # Analyze TCP flags - handle both FlagValue and int types
#         try:
#             # Convert flags to integer if it's a FlagValue object
#             if hasattr(tcp.flags, 'value'):
#                 flags_val = int(tcp.flags.value)
#             else:
#                 flags_val = int(tcp.flags)
#         except (ValueError, AttributeError):
#             flags_val = 0
        
#         flags_detail = {
#             'fin': bool(flags_val & 0x001),
#             'syn': bool(flags_val & 0x002),
#             'rst': bool(flags_val & 0x004),
#             'psh': bool(flags_val & 0x008),
#             'ack': bool(flags_val & 0x010),
#             'urg': bool(flags_val & 0x020),
#             'ece': bool(flags_val & 0x040),
#             'cwr': bool(flags_val & 0x080)
#         }
        
#         # TCP options analysis
#         options_detail = self.analyze_tcp_options(tcp)
        
#         # Calculate payload length
#         payload_length = len(tcp.payload) if tcp.payload else 0
        
#         return {
#             'source_port': tcp.sport,
#             'destination_port': tcp.dport,
#             'sequence_number': tcp.seq,
#             'acknowledgment_number': tcp.ack,
#             'header_length_bytes': tcp.dataofs * 4,
#             'header_length_words': tcp.dataofs,
#             'flags': hex(flags_val),
#             'flags_decimal': flags_val,
#             'flags_detail': flags_detail,
#             'window_size': tcp.window,
#             'checksum': hex(tcp.chksum),
#             'urgent_pointer': tcp.urgptr,
#             'options': options_detail,
#             'payload_length': payload_length,
#             'has_payload': payload_length > 0
#         }
    
#     def analyze_udp_layer(self, packet):
#         """Extract UDP layer information"""
#         if not packet.haslayer(UDP):
#             return None
        
#         udp = packet[UDP]
#         payload_length = len(udp.payload) if udp.payload else 0
        
#         return {
#             'source_port': udp.sport,
#             'destination_port': udp.dport,
#             'length': udp.len,
#             'checksum': hex(udp.chksum),
#             'payload_length': payload_length,
#             'has_payload': payload_length > 0
#         }
    
#     def analyze_tcp_options(self, tcp_layer):
#         """Analyze TCP options in detail"""
#         options_detail = []
        
#         if not tcp_layer.options:
#             return options_detail
        
#         for option in tcp_layer.options:
#             if isinstance(option, tuple):
#                 opt_kind = option[0]
#                 opt_data = option[1] if len(option) > 1 else None
                
#                 if opt_kind == 'NOP':
#                     options_detail.append({
#                         'type': 'NOP',
#                         'description': 'No Operation',
#                         'length': 1
#                     })
#                 elif opt_kind == 'Timestamp':
#                     if opt_data and len(opt_data) >= 8:
#                         tsval = struct.unpack('>I', opt_data[:4])[0]
#                         tsecr = struct.unpack('>I', opt_data[4:8])[0]
#                         options_detail.append({
#                             'type': 'Timestamp',
#                             'length': 10,
#                             'tsval': tsval,
#                             'tsecr': tsecr,
#                             'description': f'Timestamps: TSval {tsval}, TSecr {tsecr}'
#                         })
#                 elif opt_kind == 'MSS':
#                     options_detail.append({
#                         'type': 'MSS',
#                         'length': 4,
#                         'value': opt_data,
#                         'description': f'Maximum Segment Size: {opt_data}'
#                     })
#                 elif opt_kind == 'WScale':
#                     options_detail.append({
#                         'type': 'WScale',
#                         'length': 3,
#                         'value': opt_data,
#                         'description': f'Window Scale: {opt_data}'
#                     })
#                 elif opt_kind == 'SAckOK':
#                     options_detail.append({
#                         'type': 'SAckOK',
#                         'length': 2,
#                         'description': 'SACK Permitted'
#                     })
#                 else:
#                     options_detail.append({
#                         'type': str(opt_kind),
#                         'data': str(opt_data) if opt_data else None,
#                         'description': f'Option: {opt_kind}'
#                     })
        
#         return options_detail
    
#     def get_protocol_hierarchy(self, packet):
#         """Get the protocol hierarchy for the packet"""
#         protocols = []
        
#         if packet.haslayer(Ether):
#             protocols.append('eth')
#             if packet[Ether].type == 0x0800:  # IPv4
#                 protocols.append('ethertype')
        
#         if packet.haslayer(IP):
#             protocols.append('ip')
            
#             if packet.haslayer(TCP):
#                 protocols.append('tcp')
#             elif packet.haslayer(UDP):
#                 protocols.append('udp')
#             elif packet.haslayer(ICMP):
#                 protocols.append('icmp')
        
#         return protocols
    
#     def get_raw_data(self, packet, max_bytes=None):
#         """Get raw packet data as hex string"""
#         raw_data = bytes(packet)
#         if max_bytes:
#             raw_data = raw_data[:max_bytes]
        
#         return {
#             'hex_string': raw_data.hex(),
#             'hex_formatted': ' '.join([f'{b:02x}' for b in raw_data]),
#             'length': len(raw_data)
#         }
    
#     def analyze_single_frame(self, packet_index):
#         """Analyze a single frame and return structured data"""
#         packet = self.packets[packet_index]
        
#         frame_data = {
#             'frame_info': {
#                 'frame_number': packet_index + 1,
#                 'frame_length_bytes': len(packet),
#                 'frame_length_bits': len(packet) * 8,
#                 'capture_length_bytes': len(packet),
#                 'capture_length_bits': len(packet) * 8,
#                 'protocols_in_frame': self.get_protocol_hierarchy(packet)
#             }
#         }
        
#         # Add timing information
#         frame_data['timing'] = self.get_timing_info(packet_index)
        
#         # Analyze each layer
#         ethernet_info = self.analyze_ethernet_layer(packet)
#         if ethernet_info:
#             frame_data['ethernet'] = ethernet_info
        
#         ip_info = self.analyze_ip_layer(packet)
#         if ip_info:
#             frame_data['ip'] = ip_info
        
#         tcp_info = self.analyze_tcp_layer(packet)
#         if tcp_info:
#             frame_data['tcp'] = tcp_info
        
#         udp_info = self.analyze_udp_layer(packet)
#         if udp_info:
#             frame_data['udp'] = udp_info
        
#         # Add ICMP if present
#         if packet.haslayer(ICMP):
#             icmp = packet[ICMP]
#             frame_data['icmp'] = {
#                 'type': icmp.type,
#                 'code': icmp.code,
#                 'checksum': hex(icmp.chksum),
#                 'id': icmp.id if hasattr(icmp, 'id') else None,
#                 'sequence': icmp.seq if hasattr(icmp, 'seq') else None
#             }
        
#         # Add raw data (first 128 bytes)
#         frame_data['raw_data'] = self.get_raw_data(packet, max_bytes=128)
        
#         return frame_data
    
#     def analyze_all_frames(self):
#         """Analyze all frames in the PCAP file"""
#         if not self.packets:
#             if not self.load_pcap():
#                 return None
        
#         print(f"Analyzing {len(self.packets)} frames...")
#         # Analyze each frame
#         for i in range(len(self.packets)):
#             if (i + 1) % 100 == 0:  # Progress indicator
#                 print(f"Processed {i + 1}/{len(self.packets)} frames...")
            
#             try:
#                 frame_data = self.analyze_single_frame(i)
#                 self.analysis_data['frames'].append(frame_data)
#             except Exception as e:
#                 print(f"Error analyzing frame {i + 1}: {e}")
#                 # Add basic frame info even if analysis fails
#                 self.analysis_data['frames'].append({
#                     'frame_info': {
#                         'frame_number': i + 1,
#                         'frame_length_bytes': len(self.packets[i]),
#                         'error': str(e)
#                     }
#                 })
        
#         print(f"Analysis complete. Processed {len(self.packets)} frames.")
#         return self.analysis_data
    
#     def get_tcp_streams(self):
#         """Identify and group TCP streams"""
#         streams = {}
#         stream_id = 0
        
#         for i, packet in enumerate(self.packets):
#             if packet.haslayer(TCP) and packet.haslayer(IP):
#                 ip_layer = packet[IP]
#                 tcp_layer = packet[TCP]
                
#                 # Create stream identifier
#                 stream_key1 = f"{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
#                 stream_key2 = f"{ip_layer.dst}:{tcp_layer.dport}-{ip_layer.src}:{tcp_layer.sport}"
                
#                 # Check if stream already exists
#                 found_stream = None
#                 for stream_k, stream_data in streams.items():
#                     if stream_key1 in stream_data['identifiers'] or stream_key2 in stream_data['identifiers']:
#                         found_stream = stream_k
#                         break
                
#                 if found_stream is None:
#                     # New stream
#                     streams[stream_id] = {
#                         'stream_id': stream_id,
#                         'identifiers': [stream_key1, stream_key2],
#                         'packets': [i + 1],
#                         'src_ip': ip_layer.src,
#                         'dst_ip': ip_layer.dst,
#                         'src_port': tcp_layer.sport,
#                         'dst_port': tcp_layer.dport
#                     }
#                     stream_id += 1
#                 else:
#                     # Add to existing stream
#                     streams[found_stream]['packets'].append(i + 1)
        
#         return list(streams.values())
    
#     def get_dscp_name(self, dscp):
#         """Get DSCP name from value"""
#         dscp_names = {
#             0: 'CS0 (Default)',
#             8: 'CS1',
#             10: 'AF11',
#             12: 'AF12',
#             14: 'AF13',
#             16: 'CS2',
#             18: 'AF21',
#             20: 'AF22',
#             22: 'AF23',
#             24: 'CS3',
#             26: 'AF31',
#             28: 'AF32',
#             30: 'AF33',
#             32: 'CS4',
#             34: 'AF41',
#             36: 'AF42',
#             38: 'AF43',
#             40: 'CS5',
#             44: 'Voice Admit',
#             46: 'EF (Expedited Forwarding)',
#             48: 'CS6',
#             56: 'CS7'
#         }
#         return dscp_names.get(dscp, f'Unknown ({dscp})')
    
#     def get_ecn_name(self, ecn):
#         """Get ECN name from value"""
#         ecn_names = {
#             0: 'Not-ECT',
#             1: 'ECT(1)',
#             2: 'ECT(0)', 
#             3: 'CE'
#         }
#         return ecn_names.get(ecn, f'Unknown ({ecn})')
    
#     def get_protocol_name(self, protocol_num):
#         """Get protocol name from number"""
#         protocol_names = {
#             1: 'ICMP',
#             2: 'IGMP',
#             6: 'TCP',
#             17: 'UDP',
#             41: 'IPv6',
#             58: 'ICMPv6',
#             89: 'OSPF'
#         }
#         return protocol_names.get(protocol_num, f'Unknown ({protocol_num})')
    
#     def add_stream_analysis(self):
#         """Add TCP stream analysis to the data"""
#         tcp_streams = self.get_tcp_streams()
#         self.analysis_data['tcp_streams'] = tcp_streams
        
#         # Add stream index to each frame
#         for stream in tcp_streams:
#             for packet_num in stream['packets']:
#                 frame_index = packet_num - 1
#                 if frame_index < len(self.analysis_data['frames']) and 'tcp' in self.analysis_data['frames'][frame_index]:
#                     self.analysis_data['frames'][frame_index]['tcp']['stream_index'] = stream['stream_id']
    
#     def generate_statistics(self):
#         """Generate overall statistics"""
#         stats = {
#             'total_frames': len(self.analysis_data['frames']),
#             'protocol_distribution': {},
#             'size_distribution': {
#                 'min_frame_size': float('inf'),
#                 'max_frame_size': 0,
#                 'avg_frame_size': 0,
#                 'total_bytes': 0
#             },
#             'ip_addresses': set(),
#             'mac_addresses': set(),
#             'ports': set()
#         }
        
#         total_size = 0
        
#         for frame in self.analysis_data['frames']:
#             # Skip frames with errors
#             if 'error' in frame.get('frame_info', {}):
#                 continue
                
#             # Protocol distribution
#             protocols = frame['frame_info'].get('protocols_in_frame', [])
#             for protocol in protocols:
#                 stats['protocol_distribution'][protocol] = stats['protocol_distribution'].get(protocol, 0) + 1
            
#             # Size statistics
#             frame_size = frame['frame_info']['frame_length_bytes']
#             total_size += frame_size
#             stats['size_distribution']['min_frame_size'] = min(stats['size_distribution']['min_frame_size'], frame_size)
#             stats['size_distribution']['max_frame_size'] = max(stats['size_distribution']['max_frame_size'], frame_size)
            
#             # Collect addresses and ports
#             if 'ip' in frame:
#                 stats['ip_addresses'].add(frame['ip']['source_address'])
#                 stats['ip_addresses'].add(frame['ip']['destination_address'])
            
#             if 'ethernet' in frame:
#                 stats['mac_addresses'].add(frame['ethernet']['source_mac'])
#                 stats['mac_addresses'].add(frame['ethernet']['destination_mac'])
            
#             if 'tcp' in frame:
#                 stats['ports'].add(frame['tcp']['source_port'])
#                 stats['ports'].add(frame['tcp']['destination_port'])
            
#             if 'udp' in frame:
#                 stats['ports'].add(frame['udp']['source_port'])
#                 stats['ports'].add(frame['udp']['destination_port'])
        
#         # Finalize statistics
#         stats['size_distribution']['total_bytes'] = total_size
#         if stats['size_distribution']['min_frame_size'] == float('inf'):
#             stats['size_distribution']['min_frame_size'] = 0
#         stats['size_distribution']['avg_frame_size'] = total_size / len(self.analysis_data['frames']) if self.analysis_data['frames'] else 0
        
#         # Convert sets to lists for JSON serialization
#         stats['ip_addresses'] = list(stats['ip_addresses'])
#         stats['mac_addresses'] = list(stats['mac_addresses'])
#         stats['ports'] = sorted(list(stats['ports']))
        
#         self.analysis_data['statistics'] = stats
    
#     def export_json(self, output_file=None, pretty_print=True):
#         """Export analysis data as JSON"""
#         if not self.analysis_data['frames']:
#             print("No data to export. Run analyze_all_frames() first.")
#             return None
        
#         # Add statistics
#         self.generate_statistics()
        
#         # Add TCP stream analysis
#         self.add_stream_analysis()
        
#         # Prepare JSON output
#         json_output = json.dumps(
#             self.analysis_data, 
#             indent=2 if pretty_print else None,
#             ensure_ascii=False
#         )
        
#         if output_file:
#             with open(output_file, 'w') as f:
#                 f.write(json_output)
#             print(f"Analysis exported to {output_file}")
        
#         return json_output

# # Convenience functions
# # Replace the existing async function with this synchronous version
# def analyze_pcap_to_json(pcap_file, include_raw_data=True):
#     """
#     Main function to analyze PCAP and return JSON data
    
#     Args:
#         pcap_file (str): Path to PCAP file
#         include_raw_data (bool): Include raw packet data in output
    
#     Returns:
#         dict: Analysis results data
#     """
#     analyzer = PCAPAnalyzer(pcap_file)
    
#     if not analyzer.load_pcap():
#         return None
    
#     # Analyze all frames
#     analysis_data = analyzer.analyze_all_frames()
    
#     if not include_raw_data:
#         # Remove raw data to reduce file size
#         for frame in analysis_data['frames']:
#             if 'raw_data' in frame:
#                 del frame['raw_data']
    
#     # Generate statistics and stream analysis
#     analyzer.generate_statistics()
#     analyzer.add_stream_analysis()
    
#     return analysis_data

# def get_frame_json(pcap_file, frame_number):
#     """
#     Get JSON data for a specific frame
    
#     Args:
#         pcap_file (str): Path to PCAP file
#         frame_number (int): Frame number to analyze
    
#     Returns:
#         dict: Frame analysis data
#     """
#     analyzer = PCAPAnalyzer(pcap_file)
    
#     if not analyzer.load_pcap():
#         return None
    
#     if frame_number > len(analyzer.packets):
#         print(f"Frame {frame_number} not found. Total frames: {len(analyzer.packets)}")
#         return None
    
#     return analyzer.analyze_single_frame(frame_number - 1)

# def save_analysis_to_file(pcap_file, output_file, include_raw_data=True):
#     """
#     Analyze PCAP and save to JSON file
    
#     Args:
#         pcap_file (str): Path to PCAP file
#         output_file (str): Path to save JSON output
#         include_raw_data (bool): Include raw packet data in output
#     """
#     analyzer = PCAPAnalyzer(pcap_file)
    
#     if not analyzer.load_pcap():
#         return False
    
#     # Analyze all frames
#     analyzer.analyze_all_frames()
    
#     if not include_raw_data:
#         # Remove raw data to reduce file size
#         for frame in analyzer.analysis_data['frames']:
#             if 'raw_data' in frame:
#                 del frame['raw_data']
    
#     # Export to JSON file
#     json_output = analyzer.export_json(output_file)
#     return json_output is not None

# # # Example usage
# # if __name__ == "__main__":
# #     # Replace with your PCAP file path
# #     pcap_file_path = "your_capture.pcap"
    
# #     print("=== PCAP TO JSON ANALYZER ===\n")
    
# #     # Method 1: Analyze entire PCAP and save to JSON file
# #     print("Analyzing entire PCAP file...")
# #     analysis_data = analyze_pcap_to_json(
# #         pcap_file=pcap_file_path,
# #         include_raw_data=True
# #     )
    
# #     if analysis_data:
# #         # Save to file
# #         with open('pcap_analysis.json', 'w') as f:
# #             json.dump(analysis_data, f, indent=2)
        
# #         print("Analysis complete! Data saved to pcap_analysis.json")
        
# #         # Print summary
# #         print("\nSummary:")
# #         print(f"- Total frames: {analysis_data['pcap_info']['total_packets']}")
# #         print(f"- Protocol distribution: {analysis_data['statistics']['protocol_distribution']}")
# #         print(f"- Size range: {analysis_data['statistics']['size_distribution']['min_frame_size']}-{analysis_data['statistics']['size_distribution']['max_frame_size']} bytes")
# #         print(f"- Unique IP addresses: {len(analysis_data['statistics']['ip_addresses'])}")
# #         print(f"- TCP streams: {len(analysis_data.get('tcp_streams', []))}")
    
# #     # Method 2: Analyze specific frame only
# #     print("\nAnalyzing Frame 1 only:")
# #     frame_1_data = get_frame_json(pcap_file_path, 1)
# #     if frame_1_data:
# #         print(json.dumps(frame_1_data, indent=2))

# # # Additional utility for quick analysis
# # def quick_pcap_summary(pcap_file):
# #     """Quick summary without full analysis"""
# #     try:
# #         packets = rdpcap(pcap_file)
# #         summary = {
# #             'total_packets': len(packets),
# #             'first_packet_time': packets[0].time if hasattr(packets[0], 'time') else None,
# #             'last_packet_time': packets[-1].time if hasattr(packets[-1], 'time') else None,
# #             'duration': None
# #         }
        
# #         if summary['first_packet_time'] and summary['last_packet_time']:
# #             summary['duration'] = summary['last_packet_time'] - summary['first_packet_time']
        
# #         return summary
# #     except Exception as e:
# #         return {'error': str(e)}


# #!/usr/bin/env python3
# """
# Complete PCAP to JSON Analyzer
# Extracts detailed information from all frames in a PCAP file and outputs as JSON
# """

# from scapy.all import rdpcap, IP, UDP, TCP, Ether, ICMP
# import json
# import datetime
# import struct

# class PCAPAnalyzer:
#     def __init__(self, pcap_file):
#         self.pcap_file = pcap_file
#         self.packets = None
#         self.analysis_data = {
#             'pcap_info': {},
#             'frames': []
#         }
    
#     def serialize_value(self, value):
#         """Convert Scapy objects to JSON-serializable types"""
#         # Handle EDecimal and other Scapy numeric types
#         if hasattr(value, 'real'):  # EDecimal has a 'real' attribute
#             return float(value)
#         elif hasattr(value, '__int__'):
#             try:
#                 return int(value)
#             except (ValueError, TypeError):
#                 return str(value)
#         elif hasattr(value, '__float__'):
#             try:
#                 return float(value)
#             except (ValueError, TypeError):
#                 return str(value)
#         elif hasattr(value, 'value'):  # FlagValue objects
#             return int(value.value) if hasattr(value.value, '__int__') else str(value.value)
#         else:
#             return value
    
#     def load_pcap(self):
#         """Load PCAP file and basic information"""
#         try:
#             self.packets = rdpcap(self.pcap_file)
#             self.analysis_data['pcap_info'] = {
#                 'filename': self.pcap_file,
#                 'total_packets': len(self.packets),
#                 'analysis_timestamp': datetime.datetime.now().isoformat()
#             }
#             return True
#         except Exception as e:
#             print(f"Error loading PCAP file: {e}")
#             return False
    
#     def get_timing_info(self, packet_index):
#         """Calculate timing information for a packet"""
#         timing_info = {
#             'frame_number': packet_index + 1,
#             'absolute_time': None,
#             'epoch_time': None,
#             'time_delta_previous': None,
#             'time_since_first': None
#         }
        
#         current_packet = self.packets[packet_index]
        
#         if hasattr(current_packet, 'time'):
#             currentTime = float(self.serialize_value(current_packet.time))
#             timing_info['absolute_time'] = datetime.datetime.fromtimestamp(currentTime).isoformat()
#             timing_info['epoch_time'] = currentTime
            
#             # Time delta from previous frame
#             if packet_index > 0:
#                 prev_packet = self.packets[packet_index - 1]
#                 if hasattr(prev_packet, 'time'):
#                     prev_time = float(self.serialize_value(prev_packet.time))
#                     timing_info['time_delta_previous'] = currentTime - prev_time
            
#             # Time since first frame
#             if packet_index > 0:
#                 first_packet = self.packets[0]
#                 if hasattr(first_packet, 'time'):
#                     first_time = float(self.serialize_value(first_packet.time))
#                     timing_info['time_since_first'] = currentTime - first_time
        
#         return timing_info
    
#     def analyze_ethernet_layer(self, packet):
#         """Extract Ethernet layer information"""
#         if not packet.haslayer(Ether):
#             return None
        
#         eth = packet[Ether]
        
#         # Extract OUI (Organizationally Unique Identifier)
#         src_oui = eth.src.replace(':', '')[:6].upper()
#         dst_oui = eth.dst.replace(':', '')[:6].upper()
        
#         # Analyze MAC address bits
#         dst_bytes = bytes.fromhex(eth.dst.replace(':', ''))
#         src_bytes = bytes.fromhex(eth.src.replace(':', ''))
        
#         return {
#             'source_mac': str(eth.src),
#             'destination_mac': str(eth.dst),
#             'source_oui': src_oui,
#             'destination_oui': dst_oui,
#             'ethertype': hex(int(self.serialize_value(eth.type))),
#             'ethertype_decimal': int(self.serialize_value(eth.type)),
#             'destination_lg_bit': bool(dst_bytes[0] & 0x02),  # Local/Global bit
#             'destination_ig_bit': bool(dst_bytes[0] & 0x01),  # Individual/Group bit
#             'source_lg_bit': bool(src_bytes[0] & 0x02),
#             'source_ig_bit': bool(src_bytes[0] & 0x01),
#             'frame_type': 'Ethernet II'
#         }
    
#     def analyze_ip_layer(self, packet):
#         """Extract IP layer information"""
#         if not packet.haslayer(IP):
#             return None
        
#         ip = packet[IP]
        
#         # Analyze flags - handle both FlagValue and int types
#         try:
#             # Convert flags to integer if it's a FlagValue object
#             flags_val = int(self.serialize_value(ip.flags))
#         except (ValueError, AttributeError, TypeError):
#             flags_val = 0
        
#         flags_detail = {
#             'reserved': bool(flags_val & 4),
#             'dont_fragment': bool(flags_val & 2),
#             'more_fragments': bool(flags_val & 1)
#         }
        
#         # DSCP and ECN analysis
#         tos_val = int(self.serialize_value(ip.tos))
#         dscp = (tos_val >> 2) & 0x3F
#         ecn = tos_val & 0x03
        
#         return {
#             'version': int(self.serialize_value(ip.version)),
#             'header_length_bytes': int(self.serialize_value(ip.ihl)) * 4,
#             'header_length_words': int(self.serialize_value(ip.ihl)),
#             'type_of_service': hex(tos_val),
#             'dscp': dscp,
#             'ecn': ecn,
#             'dscp_name': self.get_dscp_name(dscp),
#             'ecn_name': self.get_ecn_name(ecn),
#             'total_length': int(self.serialize_value(ip.len)),
#             'identification': hex(int(self.serialize_value(ip.id))),
#             'identification_decimal': int(self.serialize_value(ip.id)),
#             'flags': hex(flags_val),
#             'flags_detail': flags_detail,
#             'fragment_offset': int(self.serialize_value(ip.frag)),
#             'ttl': int(self.serialize_value(ip.ttl)),
#             'protocol': int(self.serialize_value(ip.proto)),
#             'protocol_name': self.get_protocol_name(int(self.serialize_value(ip.proto))),
#             'header_checksum': hex(int(self.serialize_value(ip.chksum))),
#             'source_address': str(ip.src),
#             'destination_address': str(ip.dst)
#         }
    
#     def analyze_tcp_layer(self, packet):
#         """Extract TCP layer information"""
#         if not packet.haslayer(TCP):
#             return None
        
#         tcp = packet[TCP]
        
#         # Analyze TCP flags - handle both FlagValue and int types
#         try:
#             flags_val = int(self.serialize_value(tcp.flags))
#         except (ValueError, AttributeError, TypeError):
#             flags_val = 0
        
#         flags_detail = {
#             'fin': bool(flags_val & 0x001),
#             'syn': bool(flags_val & 0x002),
#             'rst': bool(flags_val & 0x004),
#             'psh': bool(flags_val & 0x008),
#             'ack': bool(flags_val & 0x010),
#             'urg': bool(flags_val & 0x020),
#             'ece': bool(flags_val & 0x040),
#             'cwr': bool(flags_val & 0x080)
#         }
        
#         # TCP options analysis
#         options_detail = self.analyze_tcp_options(tcp)
        
#         # Calculate payload length
#         payload_length = len(tcp.payload) if tcp.payload else 0
        
#         return {
#             'source_port': int(self.serialize_value(tcp.sport)),
#             'destination_port': int(self.serialize_value(tcp.dport)),
#             'sequence_number': int(self.serialize_value(tcp.seq)),
#             'acknowledgment_number': int(self.serialize_value(tcp.ack)),
#             'header_length_bytes': int(self.serialize_value(tcp.dataofs)) * 4,
#             'header_length_words': int(self.serialize_value(tcp.dataofs)),
#             'flags': hex(flags_val),
#             'flags_decimal': flags_val,
#             'flags_detail': flags_detail,
#             'window_size': int(self.serialize_value(tcp.window)),
#             'checksum': hex(int(self.serialize_value(tcp.chksum))),
#             'urgent_pointer': int(self.serialize_value(tcp.urgptr)),
#             'options': options_detail,
#             'payload_length': payload_length,
#             'has_payload': payload_length > 0
#         }
    
#     def analyze_udp_layer(self, packet):
#         """Extract UDP layer information"""
#         if not packet.haslayer(UDP):
#             return None
        
#         udp = packet[UDP]
#         payload_length = len(udp.payload) if udp.payload else 0
        
#         return {
#             'source_port': int(self.serialize_value(udp.sport)),
#             'destination_port': int(self.serialize_value(udp.dport)),
#             'length': int(self.serialize_value(udp.len)),
#             'checksum': hex(int(self.serialize_value(udp.chksum))),
#             'payload_length': payload_length,
#             'has_payload': payload_length > 0
#         }
    
#     def analyze_tcp_options(self, tcp_layer):
#         """Analyze TCP options in detail"""
#         options_detail = []
        
#         if not tcp_layer.options:
#             return options_detail
        
#         for option in tcp_layer.options:
#             if isinstance(option, tuple):
#                 opt_kind = option[0]
#                 opt_data = option[1] if len(option) > 1 else None
                
#                 if opt_kind == 'NOP':
#                     options_detail.append({
#                         'type': 'NOP',
#                         'description': 'No Operation',
#                         'length': 1
#                     })
#                 elif opt_kind == 'Timestamp':
#                     if opt_data and len(opt_data) >= 8:
#                         tsval = struct.unpack('>I', opt_data[:4])[0]
#                         tsecr = struct.unpack('>I', opt_data[4:8])[0]
#                         options_detail.append({
#                             'type': 'Timestamp',
#                             'length': 10,
#                             'tsval': tsval,
#                             'tsecr': tsecr,
#                             'description': f'Timestamps: TSval {tsval}, TSecr {tsecr}'
#                         })
#                 elif opt_kind == 'MSS':
#                     mss_val = int(self.serialize_value(opt_data)) if opt_data else 0
#                     options_detail.append({
#                         'type': 'MSS',
#                         'length': 4,
#                         'value': mss_val,
#                         'description': f'Maximum Segment Size: {mss_val}'
#                     })
#                 elif opt_kind == 'WScale':
#                     wscale_val = int(self.serialize_value(opt_data)) if opt_data else 0
#                     options_detail.append({
#                         'type': 'WScale',
#                         'length': 3,
#                         'value': wscale_val,
#                         'description': f'Window Scale: {wscale_val}'
#                     })
#                 elif opt_kind == 'SAckOK':
#                     options_detail.append({
#                         'type': 'SAckOK',
#                         'length': 2,
#                         'description': 'SACK Permitted'
#                     })
#                 else:
#                     options_detail.append({
#                         'type': str(opt_kind),
#                         'data': str(opt_data) if opt_data else None,
#                         'description': f'Option: {opt_kind}'
#                     })
        
#         return options_detail
    
#     def get_protocol_hierarchy(self, packet):
#         """Get the protocol hierarchy for the packet"""
#         protocols = []
        
#         if packet.haslayer(Ether):
#             protocols.append('eth')
#             eth_type = int(self.serialize_value(packet[Ether].type))
#             if eth_type == 0x0800:  # IPv4
#                 protocols.append('ethertype')
        
#         if packet.haslayer(IP):
#             protocols.append('ip')
            
#             if packet.haslayer(TCP):
#                 protocols.append('tcp')
#             elif packet.haslayer(UDP):
#                 protocols.append('udp')
#             elif packet.haslayer(ICMP):
#                 protocols.append('icmp')
        
#         return protocols
    
#     def get_raw_data(self, packet, max_bytes=None):
#         """Get raw packet data as hex string"""
#         raw_data = bytes(packet)
#         if max_bytes:
#             raw_data = raw_data[:max_bytes]
        
#         return {
#             'hex_string': raw_data.hex(),
#             'hex_formatted': ' '.join([f'{b:02x}' for b in raw_data]),
#             'length': len(raw_data)
#         }
    
#     def analyze_single_frame(self, packet_index):
#         """Analyze a single frame and return structured data"""
#         packet = self.packets[packet_index]
        
#         frame_data = {
#             'frame_info': {
#                 'frame_number': packet_index + 1,
#                 'frame_length_bytes': len(packet),
#                 'frame_length_bits': len(packet) * 8,
#                 'capture_length_bytes': len(packet),
#                 'capture_length_bits': len(packet) * 8,
#                 'protocols_in_frame': self.get_protocol_hierarchy(packet)
#             }
#         }
        
#         # Add timing information
#         frame_data['timing'] = self.get_timing_info(packet_index)
        
#         # Analyze each layer
#         ethernet_info = self.analyze_ethernet_layer(packet)
#         if ethernet_info:
#             frame_data['ethernet'] = ethernet_info
        
#         ip_info = self.analyze_ip_layer(packet)
#         if ip_info:
#             frame_data['ip'] = ip_info
        
#         tcp_info = self.analyze_tcp_layer(packet)
#         if tcp_info:
#             frame_data['tcp'] = tcp_info
        
#         udp_info = self.analyze_udp_layer(packet)
#         if udp_info:
#             frame_data['udp'] = udp_info
        
#         # Add ICMP if present
#         if packet.haslayer(ICMP):
#             icmp = packet[ICMP]
#             icmp_data = {
#                 'type': int(self.serialize_value(icmp.type)),
#                 'code': int(self.serialize_value(icmp.code)),
#                 'checksum': hex(int(self.serialize_value(icmp.chksum))),
#             }
            
#             # Add optional fields if they exist
#             if hasattr(icmp, 'id'):
#                 icmp_data['id'] = int(self.serialize_value(icmp.id))
#             if hasattr(icmp, 'seq'):
#                 icmp_data['sequence'] = int(self.serialize_value(icmp.seq))
                
#             frame_data['icmp'] = icmp_data
        
#         # Add raw data (first 128 bytes)
#         frame_data['raw_data'] = self.get_raw_data(packet, max_bytes=128)
        
#         return frame_data
    
#     def analyze_all_frames(self):
#         """Analyze all frames in the PCAP file"""
#         if not self.packets:
#             if not self.load_pcap():
#                 return None
        
#         print(f"Analyzing {len(self.packets)} frames...")
#         # Analyze each frame
#         for i in range(len(self.packets)):
#             if (i + 1) % 100 == 0:  # Progress indicator
#                 print(f"Processed {i + 1}/{len(self.packets)} frames...")
            
#             try:
#                 frame_data = self.analyze_single_frame(i)
#                 self.analysis_data['frames'].append(frame_data)
#             except Exception as e:
#                 print(f"Error analyzing frame {i + 1}: {e}")
#                 # Add basic frame info even if analysis fails
#                 self.analysis_data['frames'].append({
#                     'frame_info': {
#                         'frame_number': i + 1,
#                         'frame_length_bytes': len(self.packets[i]),
#                         'error': str(e)
#                     }
#                 })
        
#         print(f"Analysis complete. Processed {len(self.packets)} frames.")
#         return self.analysis_data
    
#     def get_tcp_streams(self):
#         """Identify and group TCP streams"""
#         streams = {}
#         stream_id = 0
        
#         for i, packet in enumerate(self.packets):
#             if packet.haslayer(TCP) and packet.haslayer(IP):
#                 ip_layer = packet[IP]
#                 tcp_layer = packet[TCP]
                
#                 # Create stream identifier
#                 sport = int(self.serialize_value(tcp_layer.sport))
#                 dport = int(self.serialize_value(tcp_layer.dport))
#                 src_ip = str(ip_layer.src)
#                 dst_ip = str(ip_layer.dst)
                
#                 stream_key1 = f"{src_ip}:{sport}-{dst_ip}:{dport}"
#                 stream_key2 = f"{dst_ip}:{dport}-{src_ip}:{sport}"
                
#                 # Check if stream already exists
#                 found_stream = None
#                 for stream_k, stream_data in streams.items():
#                     if stream_key1 in stream_data['identifiers'] or stream_key2 in stream_data['identifiers']:
#                         found_stream = stream_k
#                         break
                
#                 if found_stream is None:
#                     # New stream
#                     streams[stream_id] = {
#                         'stream_id': stream_id,
#                         'identifiers': [stream_key1, stream_key2],
#                         'packets': [i + 1],
#                         'src_ip': src_ip,
#                         'dst_ip': dst_ip,
#                         'src_port': sport,
#                         'dst_port': dport
#                     }
#                     stream_id += 1
#                 else:
#                     # Add to existing stream
#                     streams[found_stream]['packets'].append(i + 1)
        
#         return list(streams.values())
    
#     def get_dscp_name(self, dscp):
#         """Get DSCP name from value"""
#         dscp_names = {
#             0: 'CS0 (Default)',
#             8: 'CS1',
#             10: 'AF11',
#             12: 'AF12',
#             14: 'AF13',
#             16: 'CS2',
#             18: 'AF21',
#             20: 'AF22',
#             22: 'AF23',
#             24: 'CS3',
#             26: 'AF31',
#             28: 'AF32',
#             30: 'AF33',
#             32: 'CS4',
#             34: 'AF41',
#             36: 'AF42',
#             38: 'AF43',
#             40: 'CS5',
#             44: 'Voice Admit',
#             46: 'EF (Expedited Forwarding)',
#             48: 'CS6',
#             56: 'CS7'
#         }
#         return dscp_names.get(dscp, f'Unknown ({dscp})')
    
#     def get_ecn_name(self, ecn):
#         """Get ECN name from value"""
#         ecn_names = {
#             0: 'Not-ECT',
#             1: 'ECT(1)',
#             2: 'ECT(0)', 
#             3: 'CE'
#         }
#         return ecn_names.get(ecn, f'Unknown ({ecn})')
    
#     def get_protocol_name(self, protocol_num):
#         """Get protocol name from number"""
#         protocol_names = {
#             1: 'ICMP',
#             2: 'IGMP',
#             6: 'TCP',
#             17: 'UDP',
#             41: 'IPv6',
#             58: 'ICMPv6',
#             89: 'OSPF'
#         }
#         return protocol_names.get(protocol_num, f'Unknown ({protocol_num})')
    
#     def add_stream_analysis(self):
#         """Add TCP stream analysis to the data"""
#         tcp_streams = self.get_tcp_streams()
#         self.analysis_data['tcp_streams'] = tcp_streams
        
#         # Add stream index to each frame
#         for stream in tcp_streams:
#             for packet_num in stream['packets']:
#                 frame_index = packet_num - 1
#                 if frame_index < len(self.analysis_data['frames']) and 'tcp' in self.analysis_data['frames'][frame_index]:
#                     self.analysis_data['frames'][frame_index]['tcp']['stream_index'] = stream['stream_id']
    
#     def generate_statistics(self):
#         """Generate overall statistics"""
#         stats = {
#             'total_frames': len(self.analysis_data['frames']),
#             'protocol_distribution': {},
#             'size_distribution': {
#                 'min_frame_size': float('inf'),
#                 'max_frame_size': 0,
#                 'avg_frame_size': 0,
#                 'total_bytes': 0
#             },
#             'ip_addresses': set(),
#             'mac_addresses': set(),
#             'ports': set()
#         }
        
#         total_size = 0
        
#         for frame in self.analysis_data['frames']:
#             # Skip frames with errors
#             if 'error' in frame.get('frame_info', {}):
#                 continue
                
#             # Protocol distribution
#             protocols = frame['frame_info'].get('protocols_in_frame', [])
#             for protocol in protocols:
#                 stats['protocol_distribution'][protocol] = stats['protocol_distribution'].get(protocol, 0) + 1
            
#             # Size statistics
#             frame_size = frame['frame_info']['frame_length_bytes']
#             total_size += frame_size
#             stats['size_distribution']['min_frame_size'] = min(stats['size_distribution']['min_frame_size'], frame_size)
#             stats['size_distribution']['max_frame_size'] = max(stats['size_distribution']['max_frame_size'], frame_size)
            
#             # Collect addresses and ports
#             if 'ip' in frame:
#                 stats['ip_addresses'].add(frame['ip']['source_address'])
#                 stats['ip_addresses'].add(frame['ip']['destination_address'])
            
#             if 'ethernet' in frame:
#                 stats['mac_addresses'].add(frame['ethernet']['source_mac'])
#                 stats['mac_addresses'].add(frame['ethernet']['destination_mac'])
            
#             if 'tcp' in frame:
#                 stats['ports'].add(frame['tcp']['source_port'])
#                 stats['ports'].add(frame['tcp']['destination_port'])
            
#             if 'udp' in frame:
#                 stats['ports'].add(frame['udp']['source_port'])
#                 stats['ports'].add(frame['udp']['destination_port'])
        
#         # Finalize statistics
#         stats['size_distribution']['total_bytes'] = total_size
#         if stats['size_distribution']['min_frame_size'] == float('inf'):
#             stats['size_distribution']['min_frame_size'] = 0
#         stats['size_distribution']['avg_frame_size'] = total_size / len(self.analysis_data['frames']) if self.analysis_data['frames'] else 0
        
#         # Convert sets to lists for JSON serialization
#         stats['ip_addresses'] = list(stats['ip_addresses'])
#         stats['mac_addresses'] = list(stats['mac_addresses'])
#         stats['ports'] = sorted(list(stats['ports']))
        
#         self.analysis_data['statistics'] = stats
    
#     def export_json(self, output_file=None, pretty_print=True):
#         """Export analysis data as JSON"""
#         if not self.analysis_data['frames']:
#             print("No data to export. Run analyze_all_frames() first.")
#             return None
        
#         # Add statistics
#         self.generate_statistics()
        
#         # Add TCP stream analysis
#         self.add_stream_analysis()
        
#         # Prepare JSON output
#         json_output = json.dumps(
#             self.analysis_data, 
#             indent=2 if pretty_print else None,
#             ensure_ascii=False
#         )
        
#         if output_file:
#             with open(output_file, 'w') as f:
#                 f.write(json_output)
#             print(f"Analysis exported to {output_file}")
        
#         return json_output

# # Convenience functions
# def analyze_pcap_to_json(pcap_file, include_raw_data=True):
#     """
#     Main function to analyze PCAP and return JSON data
    
#     Args:
#         pcap_file (str): Path to PCAP file
#         include_raw_data (bool): Include raw packet data in output
    
#     Returns:
#         dict: Analysis results data
#     """
#     analyzer = PCAPAnalyzer(pcap_file)
    
#     if not analyzer.load_pcap():
#         return None
    
#     # Analyze all frames
#     analysis_data = analyzer.analyze_all_frames()
    
#     if not include_raw_data:
#         # Remove raw data to reduce file size
#         for frame in analysis_data['frames']:
#             if 'raw_data' in frame:
#                 del frame['raw_data']
    
#     # Generate statistics and stream analysis
#     analyzer.generate_statistics()
#     analyzer.add_stream_analysis()
    
#     return analysis_data

# def get_frame_json(pcap_file, frame_number):
#     """
#     Get JSON data for a specific frame
    
#     Args:
#         pcap_file (str): Path to PCAP file
#         frame_number (int): Frame number to analyze
    
#     Returns:
#         dict: Frame analysis data
#     """
#     analyzer = PCAPAnalyzer(pcap_file)
    
#     if not analyzer.load_pcap():
#         return None
    
#     if frame_number > len(analyzer.packets):
#         print(f"Frame {frame_number} not found. Total frames: {len(analyzer.packets)}")
#         return None
    
#     return analyzer.analyze_single_frame(frame_number - 1)

# def save_analysis_to_file(pcap_file, output_file, include_raw_data=True):
#     """
#     Analyze PCAP and save to JSON file
    
#     Args:
#         pcap_file (str): Path to PCAP file
#         output_file (str): Path to save JSON output
#         include_raw_data (bool): Include raw packet data in output
#     """
#     analyzer = PCAPAnalyzer(pcap_file)
    
#     if not analyzer.load_pcap():
#         return False
    
#     # Analyze all frames
#     analyzer.analyze_all_frames()
    
#     if not include_raw_data:
#         # Remove raw data to reduce file size
#         for frame in analyzer.analysis_data['frames']:
#             if 'raw_data' in frame:
#                 del frame['raw_data']
    
#     # Export to JSON file
#     json_output = analyzer.export_json(output_file)
#     return json_output is not None



#!/usr/bin/env python3
"""
Complete PCAP to JSON Analyzer - Wireshark-style output
Extracts detailed information from all frames in a PCAP file and outputs as JSON list
"""

from scapy.all import rdpcap, IP, UDP, TCP, Ether, ICMP, ARP, DNS, Raw
from typing import List, Dict, Any
import json
import datetime
import struct
import binascii

class PCAPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = None
    
    def serialize_value(self, value):
        """Convert Scapy objects to JSON-serializable types"""
        # Handle EDecimal and other Scapy numeric types
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
        """Load PCAP file"""
        try:
            self.packets = rdpcap(self.pcap_file)
            return True
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            return False
    
    def get_protocol_name(self, packet):
        """Determine the main protocol for display"""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(IP):
            return "IP"
        else:
            try:
                return packet.lastlayer().__class__.__name__
            except:
                return "Unknown"
    
    def generate_info_string(self, packet):
        """Generate Wireshark-style info string"""
        info_parts = []
        
        try:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                if int(self.serialize_value(arp.op)) == 1:  # Request
                    info_parts.append(f"Who has {arp.pdst}? Tell {arp.psrc}")
                elif int(self.serialize_value(arp.op)) == 2:  # Reply
                    info_parts.append(f"{arp.psrc} is at {arp.hwsrc}")
                else:
                    info_parts.append("ARP packet")
            
            elif packet.haslayer(TCP):
                tcp = packet[TCP]
                sport = int(self.serialize_value(tcp.sport))
                dport = int(self.serialize_value(tcp.dport))
                flags = int(self.serialize_value(tcp.flags))
                seq = int(self.serialize_value(tcp.seq))
                ack = int(self.serialize_value(tcp.ack))
                
                parts = [f"{sport} → {dport}"]
                
                # Add flag names
                flag_names = []
                if flags & 0x002: flag_names.append("SYN")
                if flags & 0x010: flag_names.append("ACK")
                if flags & 0x001: flag_names.append("FIN")
                if flags & 0x004: flag_names.append("RST")
                if flags & 0x008: flag_names.append("PSH")
                if flags & 0x020: flag_names.append("URG")
                
                if flag_names:
                    parts.append(f"[{', '.join(flag_names)}]")
                
                parts.append(f"Seq={seq}")
                if flags & 0x010:  # ACK flag set
                    parts.append(f"Ack={ack}")
                
                # Check for HTTP
                if packet.haslayer(Raw):
                    try:
                        data = packet[Raw].load.decode(errors="ignore")
                        if "HTTP" in data or "GET" in data or "POST" in data:
                            first_line = data.split("\r\n")[0].strip()
                            if first_line:
                                parts.append(f"HTTP: {first_line}")
                    except:
                        pass
                
                info_parts.append(" ".join(parts))
            
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                sport = int(self.serialize_value(udp.sport))
                dport = int(self.serialize_value(udp.dport))
                length = int(self.serialize_value(udp.len))
                
                parts = [f"{sport} → {dport}"]
                parts.append(f"Len={length}")
                
                # Check for DNS
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    if int(self.serialize_value(dns.qr)) == 0 and dns.qd:  # Query
                        qname = dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
                        parts.append(f"DNS Query: {qname}")
                    elif int(self.serialize_value(dns.qr)) == 1:  # Response
                        parts.append("DNS Response")
                
                info_parts.append(" ".join(parts))
            
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                icmp_type = int(self.serialize_value(icmp.type))
                icmp_code = int(self.serialize_value(icmp.code))
                
                if icmp_type == 8:
                    info_parts.append("Echo (ping) request")
                elif icmp_type == 0:
                    info_parts.append("Echo (ping) reply")
                else:
                    info_parts.append(f"ICMP Type={icmp_type} Code={icmp_code}")
            
            elif packet.haslayer(IP):
                ip = packet[IP]
                protocol = int(self.serialize_value(ip.proto))
                info_parts.append(f"IP Protocol={protocol}")
            
            else:
                try:
                    info_parts.append(packet.summary())
                except:
                    info_parts.append("Unknown packet")
        
        except Exception as e:
            info_parts.append(f"Error parsing: {str(e)}")
        
        return "; ".join(info_parts) if info_parts else "Packet"
    
    def analyze_ethernet_layer(self, packet):
        """Extract Ethernet layer information"""
        if not packet.haslayer(Ether):
            return None
        
        eth = packet[Ether]
        return {
            "src_mac": str(eth.src),
            "dst_mac": str(eth.dst),
            "type": int(self.serialize_value(eth.type))
        }
    
    def analyze_ip_layer(self, packet):
        """Extract IP layer information"""
        if not packet.haslayer(IP):
            return None
        
        ip = packet[IP]
        return {
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
            "protocol": int(self.serialize_value(ip.proto)),
            "ttl": int(self.serialize_value(ip.ttl)),
            "header_length": int(self.serialize_value(ip.ihl)),
            "total_length": int(self.serialize_value(ip.len)),
            "identification": int(self.serialize_value(ip.id)),
            "flags": int(self.serialize_value(ip.flags)),
            "fragment_offset": int(self.serialize_value(ip.frag)),
            "checksum": int(self.serialize_value(ip.chksum)),
            "version": int(self.serialize_value(ip.version)),
            "tos": int(self.serialize_value(ip.tos))
        }
    
    def analyze_tcp_layer(self, packet):
        """Extract TCP layer information"""
        if not packet.haslayer(TCP):
            return None
        
        tcp = packet[TCP]
        flags_val = int(self.serialize_value(tcp.flags))
        
        return {
            "src_port": int(self.serialize_value(tcp.sport)),
            "dst_port": int(self.serialize_value(tcp.dport)),
            "flags": str(tcp.flags),
            "flags_value": flags_val,
            "seq": int(self.serialize_value(tcp.seq)),
            "ack": int(self.serialize_value(tcp.ack)),
            "window": int(self.serialize_value(tcp.window)),
            "checksum": int(self.serialize_value(tcp.chksum)),
            "urgent_pointer": int(self.serialize_value(tcp.urgptr)),
            "header_length": int(self.serialize_value(tcp.dataofs))
        }
    
    def analyze_udp_layer(self, packet):
        """Extract UDP layer information"""
        if not packet.haslayer(UDP):
            return None
        
        udp = packet[UDP]
        return {
            "src_port": int(self.serialize_value(udp.sport)),
            "dst_port": int(self.serialize_value(udp.dport)),
            "length": int(self.serialize_value(udp.len)),
            "checksum": int(self.serialize_value(udp.chksum))
        }
    
    def analyze_arp_layer(self, packet):
        """Extract ARP layer information"""
        if not packet.haslayer(ARP):
            return None
        
        arp = packet[ARP]
        return {
            "hwtype": int(self.serialize_value(arp.hwtype)),
            "ptype": int(self.serialize_value(arp.ptype)),
            "hwlen": int(self.serialize_value(arp.hwlen)),
            "plen": int(self.serialize_value(arp.plen)),
            "op": int(self.serialize_value(arp.op)),
            "src_mac": str(arp.hwsrc),
            "src_ip": str(arp.psrc),
            "dst_mac": str(arp.hwdst),
            "dst_ip": str(arp.pdst)
        }
    
    def analyze_icmp_layer(self, packet):
        """Extract ICMP layer information"""
        if not packet.haslayer(ICMP):
            return None
        
        icmp = packet[ICMP]
        icmp_data = {
            "type": int(self.serialize_value(icmp.type)),
            "code": int(self.serialize_value(icmp.code)),
            "checksum": int(self.serialize_value(icmp.chksum))
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
            "id": int(self.serialize_value(dns.id)),
            "qr": int(self.serialize_value(dns.qr)),
            "opcode": int(self.serialize_value(dns.opcode)),
            "rcode": int(self.serialize_value(dns.rcode))
        }
        
        # Query information
        if dns.qd:
            qname = dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
            dns_data.update({
                "query": qname,
                "query_type": int(self.serialize_value(dns.qd.qtype))
            })
        
        return dns_data
    
    def analyze_application_layer(self, packet):
        """Analyze application layer protocols"""
        if not packet.haslayer(Raw):
            return None
        
        try:
            data = packet[Raw].load.decode(errors="ignore")
            
            # HTTP detection
            if any(keyword in data for keyword in ["HTTP", "GET", "POST", "PUT", "DELETE"]):
                first_line = data.split("\r\n")[0].strip()
                return {
                    "protocol": "HTTP",
                    "info": first_line,
                    "data_preview": data[:200]  # First 200 chars
                }
        except Exception:
            pass
        
        return None
    
    def analyze_single_packet(self, packet_index):
        """Analyze a single packet in Wireshark-style format"""
        packet = self.packets[packet_index]
        
        # Calculate relative timestamp
        try:
            current_time = float(self.serialize_value(packet.time))
            first_time = float(self.serialize_value(self.packets[0].time))
            relative_time = round(current_time - first_time, 6)
            timestamp_str = datetime.datetime.fromtimestamp(current_time).isoformat()
        except Exception:
            relative_time = 0.0
            timestamp_str = ""
            current_time = 0.0
        
        # Basic packet info
        packet_data = {
            "no": packet_index + 1,
            "time": relative_time,
            "timestamp": timestamp_str,
            "length": len(packet),
            "protocol": self.get_protocol_name(packet),
            "info": self.generate_info_string(packet),
            "packet": {},
            "raw": {
                "hex": binascii.hexlify(bytes(packet)).decode(),
                "ascii": "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes(packet)])
            }
        }
        
        # Add source and destination from IP layer if available
        if packet.haslayer(IP):
            ip = packet[IP]
            packet_data["source"] = str(ip.src)
            packet_data["destination"] = str(ip.dst)
        else:
            packet_data["source"] = "-"
            packet_data["destination"] = "-"
        
        # Analyze layers
        ethernet_info = self.analyze_ethernet_layer(packet)
        if ethernet_info:
            packet_data["packet"]["ethernet"] = ethernet_info
        
        ip_info = self.analyze_ip_layer(packet)
        if ip_info:
            packet_data["packet"]["ip"] = ip_info
        
        tcp_info = self.analyze_tcp_layer(packet)
        if tcp_info:
            packet_data["packet"]["tcp"] = tcp_info
        
        udp_info = self.analyze_udp_layer(packet)
        if udp_info:
            packet_data["packet"]["udp"] = udp_info
        
        arp_info = self.analyze_arp_layer(packet)
        if arp_info:
            packet_data["packet"]["arp"] = arp_info
        
        icmp_info = self.analyze_icmp_layer(packet)
        if icmp_info:
            packet_data["packet"]["icmp"] = icmp_info
        
        dns_info = self.analyze_dns_layer(packet)
        if dns_info:
            packet_data["packet"]["dns"] = dns_info
        
        app_info = self.analyze_application_layer(packet)
        if app_info:
            packet_data["packet"]["application"] = app_info
            # Update protocol and info if application layer detected
            packet_data["protocol"] = app_info["protocol"]
            packet_data["info"] = app_info["info"]
        
        return packet_data
    
    def get_protocol_name(self, packet):
        """Determine the main protocol for display"""
        # Check for application protocols first
        if packet.haslayer(Raw):
            try:
                data = packet[Raw].load.decode(errors="ignore")
                if any(keyword in data for keyword in ["HTTP", "GET", "POST", "PUT", "DELETE"]):
                    return "HTTP"
            except:
                pass
        
        if packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(IP):
            return "IP"
        else:
            try:
                return packet.lastlayer().__class__.__name__
            except:
                return "Unknown"
    
    def generate_info_string(self, packet):
        """Generate Wireshark-style info string"""
        info_parts = []
        
        try:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                op = int(self.serialize_value(arp.op))
                if op == 1:  # Request
                    info_parts.append(f"Who has {arp.pdst}? Tell {arp.psrc}")
                elif op == 2:  # Reply
                    info_parts.append(f"{arp.psrc} is at {arp.hwsrc}")
                else:
                    info_parts.append("ARP packet")
            
            elif packet.haslayer(TCP):
                tcp = packet[TCP]
                sport = int(self.serialize_value(tcp.sport))
                dport = int(self.serialize_value(tcp.dport))
                flags = int(self.serialize_value(tcp.flags))
                
                parts = [f"{sport} → {dport}"]
                
                # Add flag names
                flag_names = []
                if flags & 0x002: flag_names.append("SYN")
                if flags & 0x010: flag_names.append("ACK")
                if flags & 0x001: flag_names.append("FIN")
                if flags & 0x004: flag_names.append("RST")
                if flags & 0x008: flag_names.append("PSH")
                if flags & 0x020: flag_names.append("URG")
                
                if flag_names:
                    parts.append(f"[{', '.join(flag_names)}]")
                
                # Check for HTTP in payload
                if packet.haslayer(Raw):
                    try:
                        data = packet[Raw].load.decode(errors="ignore")
                        if any(keyword in data for keyword in ["HTTP", "GET", "POST", "PUT", "DELETE"]):
                            first_line = data.split("\r\n")[0].strip()
                            if first_line:
                                return f"HTTP: {first_line}"
                    except:
                        pass
                
                info_parts.append(" ".join(parts))
            
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                sport = int(self.serialize_value(udp.sport))
                dport = int(self.serialize_value(udp.dport))
                
                # Check for DNS first
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    qr = int(self.serialize_value(dns.qr))
                    if qr == 0 and dns.qd:  # Query
                        qname = dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
                        info_parts.append(f"DNS Query: {qname}")
                    elif qr == 1:  # Response
                        info_parts.append("DNS Response")
                    else:
                        info_parts.append(f"DNS {sport} → {dport}")
                else:
                    info_parts.append(f"UDP {sport} → {dport}")
            
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                icmp_type = int(self.serialize_value(icmp.type))
                
                if icmp_type == 8:
                    info_parts.append("Echo (ping) request")
                elif icmp_type == 0:
                    info_parts.append("Echo (ping) reply")
                else:
                    info_parts.append(f"ICMP Type={icmp_type}")
            
            elif packet.haslayer(IP):
                ip = packet[IP]
                protocol = int(self.serialize_value(ip.proto))
                info_parts.append(f"IP Protocol={protocol}")
            
            else:
                try:
                    info_parts.append(packet.summary())
                except:
                    info_parts.append("Unknown packet")
        
        except Exception as e:
            info_parts.append(f"Error: {str(e)}")
        
        return "; ".join(info_parts) if info_parts else "Packet"
    
    def analyze_all_packets(self):
        """Analyze all packets and return list similar to old format"""
        if not self.packets:
            if not self.load_pcap():
                return []
        
        print(f"Analyzing {len(self.packets)} packets...")
        packet_list = []
        
        for i in range(len(self.packets)):
            if (i + 1) % 100 == 0:  # Progress indicator
                print(f"Processed {i + 1}/{len(self.packets)} packets...")
            
            try:
                packet_data = self.analyze_single_packet(i)
                packet_list.append(packet_data)
            except Exception as e:
                print(f"Error analyzing packet {i + 1}: {e}")
                # Add basic packet info even if analysis fails
                packet_list.append({
                    "no": i + 1,
                    "time": 0.0,
                    "timestamp": "",
                    "source": "Error",
                    "destination": "Error",
                    "protocol": "Error",
                    "length": 0,
                    "info": f"Analysis error: {str(e)}",
                    "packet": {},
                    "raw": {"hex": "", "ascii": ""}
                })
        
        print(f"Analysis complete. Processed {len(self.packets)} packets.")
        return packet_list

def ensure_json_serializable(obj):
    """Recursively convert objects to JSON serializable types"""
    if isinstance(obj, dict):
        return {k: ensure_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [ensure_json_serializable(item) for item in obj]
    elif isinstance(obj, set):
        return list(obj)
    elif hasattr(obj, 'isoformat'):  # datetime objects
        return obj.isoformat()
    elif hasattr(obj, 'real'):  # EDecimal
        return float(obj)
    elif hasattr(obj, '__float__'):
        try:
            return float(obj)
        except (ValueError, TypeError):
            return str(obj)
    elif hasattr(obj, '__int__'):
        try:
            return int(obj)
        except (ValueError, TypeError):
            return str(obj)
    elif hasattr(obj, '__str__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj

# Main analysis function to match old interface
def analyze_pcap_to_json(pcap_file, include_raw_data=True):
    """
    Main function to analyze PCAP and return list of packets (matching old format)
    
    Args:
        pcap_file (str): Path to PCAP file
        include_raw_data (bool): Include raw packet data in output
    
    Returns:
        list: List of packet analysis data (Wireshark-style)
    """
    analyzer = PCAPAnalyzer(pcap_file)
    
    if not analyzer.load_pcap():
        return []
    
    # Analyze all packets
    packet_list = analyzer.analyze_all_packets()
    
    if not include_raw_data:
        # Remove raw data to reduce size
        for packet in packet_list:
            if 'raw' in packet:
                del packet['raw']
    
    # Ensure all data is JSON serializable
    return ensure_json_serializable(packet_list)

# Synchronous analysis function using Scapy (matching old interface)
def analyze_pcap_sync(pcap_file_path: str) -> List[Dict[str, Any]]:
    """Synchronous PCAP analysis using Scapy - returns packet list"""
    try:
        return analyze_pcap_to_json(pcap_file_path)
    except Exception as e:
        raise RuntimeError(f"Analysis failed: {str(e)}")

# Async wrapper for FastAPI (matching old interface)
async def pysharkAnalysis(pcap_file_path: str) -> List[Dict[str, Any]]:
    """Analyze PCAP file - async wrapper around Scapy analysis"""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    
    executor = ThreadPoolExecutor(max_workers=4)
    
    def _analyze():
        return analyze_pcap_sync(pcap_file_path)
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, _analyze)