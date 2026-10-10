from .base_extractor import BasePCAPExtractor

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class HttpExtractor(BasePCAPExtractor):
    """
    Extracts HTTP traffic (requests, URIs, User-Agents, Host headers, Methods).
    """

    def extract(self):
        if not SCAPY_AVAILABLE:
            return self.build_result(
                artifact="HTTP",
                status="FAILED",
                message="Scapy is not installed."
            )

        http_requests = []
        try:
            packets = rdpcap(str(self.pcap_path))
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")

                    # Check for HTTP request methods
                    if any(payload.startswith(method) for method in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                        lines = payload.split("\r\n")
                        first_line = lines[0].split(" ")
                        method = first_line[0]
                        uri = first_line[1] if len(first_line) > 1 else ""

                        host = ""
                        user_agent = ""
                        for line in lines[1:]:
                            if line.lower().startswith("host:"):
                                host = line.split(":", 1)[1].strip()
                            elif line.lower().startswith("user-agent:"):
                                user_agent = line.split(":", 1)[1].strip()

                        ip_src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "")
                        ip_dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "")

                        http_requests.append({
                            "src_ip": ip_src,
                            "dst_ip": ip_dst,
                            "method": method,
                            "host": host,
                            "uri": uri,
                            "user_agent": user_agent,
                            "full_url": f"http://{host}{uri}" if host else uri
                        })

            status = "SUCCESS" if http_requests else "SKIPPED"
            return self.build_result(
                artifact="HTTP",
                status=status,
                count=len(http_requests),
                message=f"Extracted {len(http_requests)} HTTP requests.",
                data=http_requests
            )
        except Exception as e:
            return self.build_result(
                artifact="HTTP",
                status="FAILED",
                message=f"Error reading PCAP: {e}"
            )
