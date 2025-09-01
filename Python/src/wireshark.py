from scapy.all import rdpcap, Ether, IP, TCP, UDP, Raw, DNS
import binascii
import json


def wireshark_analysis(pathUrl):
    print(pathUrl)
    packets = rdpcap(pathUrl)
    print(packets)
    packet_list = []
    for i, pkt in enumerate(packets, start=1):
        print(pkt)
        pkt_info = {
            "no": i,
            "timestamp": float(pkt.time),  # Convert to float for JSON serialization
            "length": len(pkt),
            "info": "",
            "packet": {},
            "raw": {
                "hex": binascii.hexlify(bytes(pkt)).decode(),
                "ascii": "".join([chr(b) if 32 <= b <= 126 else "." for b in bytes(pkt)])
            }
        }

        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            pkt_info["packet"]["ethernet"] = {
                "src_mac": eth.src,
                "dst_mac": eth.dst,
                "type": eth.type
            }

        if pkt.haslayer(IP):
            ip = pkt[IP]
            pkt_info["packet"]["ip"] = {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": ip.proto,
                "ttl": ip.ttl,
                "header_length": ip.ihl
            }

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            pkt_info["packet"]["tcp"] = {
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "flags": str(tcp.flags),
                "seq": tcp.seq,
                "ack": tcp.ack,
                "window": tcp.window
            }
            pkt_info["info"] = f"TCP {tcp.sport} → {tcp.dport} Flags={tcp.flags}"

            if pkt.haslayer(Raw):
                try:
                    data = pkt[Raw].load.decode(errors="ignore")
                    if "HTTP" in data or "GET" in data or "POST" in data:
                        pkt_info["packet"]["application"] = {
                            "protocol": "HTTP",
                            "info": data.split("\r\n")[0]
                        }
                        pkt_info["info"] = pkt_info["packet"]["application"]["info"]
                except Exception:
                    pass

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            pkt_info["packet"]["udp"] = {
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "length": udp.len
            }
            pkt_info["info"] = f"UDP {udp.sport} → {udp.dport}"

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd is not None:
                    pkt_info["packet"]["application"] = {
                        "protocol": "DNS",
                        "query": dns.qd.qname.decode(),
                        "query_type": dns.qd.qtype
                    }
                    pkt_info["info"] = f"DNS Query {dns.qd.qname.decode()}"

        packet_list.append(pkt_info)
    
    return packet_list