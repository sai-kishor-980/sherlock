from .base_extractor import BasePCAPExtractor

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TlsExtractor(BasePCAPExtractor):
    """
    Extracts TLS SNI (Server Name Indication) domain names from Client Hello handshakes.
    """

    def extract(self):
        if not SCAPY_AVAILABLE:
            return self.build_result(
                artifact="TLS",
                status="FAILED",
                message="Scapy is not installed."
            )

        tls_records = []
        try:
            packets = rdpcap(str(self.pcap_path))
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    payload = pkt[Raw].load

                    # TLS Client Hello Handshake (ContentType 0x16, Version 0x0301/0x0303, HandshakeType 0x01)
                    if len(payload) > 43 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01:
                        try:
                            # Parse SNI extension from Client Hello payload bytes
                            sni_name = self._parse_sni(payload)
                            if sni_name:
                                ip_src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "")
                                ip_dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "")
                                port_dst = pkt[TCP].dport

                                tls_records.append({
                                    "src_ip": ip_src,
                                    "dst_ip": ip_dst,
                                    "dst_port": port_dst,
                                    "sni_server_name": sni_name
                                })
                        except Exception:
                            continue

            status = "SUCCESS" if tls_records else "SKIPPED"
            return self.build_result(
                artifact="TLS",
                status=status,
                count=len(tls_records),
                message=f"Extracted {len(tls_records)} TLS SNI records.",
                data=tls_records
            )
        except Exception as e:
            return self.build_result(
                artifact="TLS",
                status="FAILED",
                message=f"Error reading PCAP: {e}"
            )

    def _parse_sni(self, payload):
        # Locate Extension Type 0x0000 (server_name) in TLS Client Hello bytes
        try:
            pos = 43  # Skip fixed header fields
            if pos >= len(payload):
                return None

            session_id_len = payload[pos]
            pos += 1 + session_id_len
            if pos + 2 > len(payload):
                return None

            cipher_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + cipher_len
            if pos >= len(payload):
                return None

            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return None

            ext_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            end_ext = pos + ext_len

            while pos + 4 <= end_ext and pos + 4 <= len(payload):
                ext_type = int.from_bytes(payload[pos:pos+2], "big")
                ext_data_len = int.from_bytes(payload[pos+2:pos+4], "big")
                pos += 4

                if ext_type == 0:  # SNI extension
                    if pos + 5 <= len(payload):
                        name_len = int.from_bytes(payload[pos+3:pos+5], "big")
                        name_bytes = payload[pos+5:pos+5+name_len]
                        return name_bytes.decode("utf-8", errors="ignore")
                pos += ext_data_len
        except Exception:
            pass
        return None
