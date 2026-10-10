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