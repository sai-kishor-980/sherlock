import json
from pathlib import Path


class PCAPMerger:
    """
    Saves the final PCAP extraction network artifacts to disk.
    """

    @staticmethod
    def write(summary, output_directory):
        out_path = Path(output_directory)
        out_path.mkdir(parents=True, exist_ok=True)

        output_file = out_path / "network_summary.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)

        return output_file
