from pathlib import Path


class PCAPContext:
    """
    Context object passed to all PCAP network extractors.
    """

    def __init__(self, pcap_path, output_dir):

        self.pcap_path = Path(pcap_path)

        self.output_dir = Path(output_dir)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )
        self._packets = None

    def get_packets(self, max_packets=30000):
        if self._packets is not None:
            return self._packets

        packets = []
        try:
            from scapy.all import PcapReader
            reader = PcapReader(str(self.pcap_path))
            for i, pkt in enumerate(reader):
                packets.append(pkt)
                if max_packets and i + 1 >= max_packets:
                    break
            reader.close()
        except Exception:
            try:
                from scapy.all import rdpcap
                raw_pkts = rdpcap(str(self.pcap_path))
                packets = list(raw_pkts[:max_packets]) if max_packets else list(raw_pkts)
            except Exception:
                packets = []

        self._packets = packets
        return self._packets