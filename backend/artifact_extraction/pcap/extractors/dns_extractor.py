import math
from .base_extractor import BasePCAPExtractor

try:
    from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP, IPv6, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def calculate_entropy(domain):
    if not domain:
        return 0.0
    probabilities = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * math.log2(p) for p in probabilities)


class DnsExtractor(BasePCAPExtractor):
    """
    Extracts DNS queries and responses from PCAP network captures.
    Detects high-entropy domains (potential DGA / Command & Control channels).
    """

    def extract(self):
        if not SCAPY_AVAILABLE:
            return self.build_result(
                artifact="DNS",
                status="FAILED",
                message="Scapy is not installed."
            )

        dns_records = []
        try:
            packets = self.get_packets()
            for pkt in packets:
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    ip_src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "")
                    ip_dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "")

                    dns_layer = pkt[DNS]
                    query_name = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".") if dns_layer.qd else ""
                    query_type = dns_layer.qd.qtype if dns_layer.qd else 0

                    entropy = calculate_entropy(query_name)
                    suspicious_dga = entropy > 3.8 and len(query_name) > 12

                    answers = []
                    if dns_layer.an:
                        for i in range(dns_layer.ancount):
                            rr = dns_layer.an[i]
                            if hasattr(rr, "rdata"):
                                rdata = rr.rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode("utf-8", errors="ignore")
                                answers.append(str(rdata))

                    dns_records.append({
                        "src_ip": ip_src,
                        "dst_ip": ip_dst,
                        "query": query_name,
                        "query_type": query_type,
                        "entropy": round(entropy, 2),
                        "suspicious_dga": suspicious_dga,
                        "answers": answers
                    })

            status = "SUCCESS" if dns_records else "SKIPPED"
            return self.build_result(
                artifact="DNS",
                status=status,
                count=len(dns_records),
                message=f"Extracted {len(dns_records)} DNS queries.",
                data=dns_records
            )
        except Exception as e:
            return self.build_result(
                artifact="DNS",
                status="FAILED",
                message=f"Error reading PCAP: {e}"
            )
