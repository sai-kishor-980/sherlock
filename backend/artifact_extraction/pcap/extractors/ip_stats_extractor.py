from collections import defaultdict
from .base_extractor import BasePCAPExtractor

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class IpStatsExtractor(BasePCAPExtractor):
    """
    Summarizes IP conversation statistics, protocol distributions, and active port counts.
    """

    def extract(self):
        if not SCAPY_AVAILABLE:
            return self.build_result(
                artifact="IP_Stats",
                status="FAILED",
                message="Scapy is not installed."
            )

        ip_conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
        protocols = defaultdict(int)
        ports = defaultdict(int)

        try:
            packets = rdpcap(str(self.pcap_path))
            for pkt in packets:
                pkt_len = len(pkt)
                src = None
                dst = None

                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst

                if src and dst:
                    pair = f"{src} <-> {dst}"
                    ip_conversations[pair]["packets"] += 1
                    ip_conversations[pair]["bytes"] += pkt_len

                if pkt.haslayer(TCP):
                    protocols["TCP"] += 1
                    ports[pkt[TCP].dport] += 1
                elif pkt.haslayer(UDP):
                    protocols["UDP"] += 1
                    ports[pkt[UDP].dport] += 1
                elif pkt.haslayer(ICMP):
                    protocols["ICMP"] += 1

            formatted_convs = [
                {"conversation": k, "packets": v["packets"], "bytes": v["bytes"]}
                for k, v in sorted(ip_conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)
            ]

            stats_data = {
                "total_packets": len(packets),
                "protocol_distribution": dict(protocols),
                "top_destination_ports": dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]),
                "conversations": formatted_convs[:50]
            }

            return self.build_result(
                artifact="IP_Stats",
                status="SUCCESS",
                count=len(packets),
                message=f"Analyzed {len(packets)} packets across {len(ip_conversations)} conversations.",
                data=stats_data
            )
        except Exception as e:
            return self.build_result(
                artifact="IP_Stats",
                status="FAILED",
                message=f"Error reading PCAP: {e}"
            )
