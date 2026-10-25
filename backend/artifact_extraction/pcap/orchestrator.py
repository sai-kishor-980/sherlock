import argparse
import json
import os
from pathlib import Path

from context import PCAPContext
from collector import PCAPCollector
from merger import PCAPMerger
from extractors import EXTRACTOR_MAP
from config import PLUGIN_FILE, DEFAULT_OUTPUT_DIR


def main():
    parser = argparse.ArgumentParser(
        description="PCAP Network Traffic Forensic Extractor"
    )

    parser.add_argument(
        "pcap",
        help="Path to network capture file (.pcap / .pcapng)"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Output directory for PCAP extraction results"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("PCAP Network Traffic Artifact Extraction")
    print("=" * 60)

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"[!] Error: PCAP file not found: {pcap_path}")
        return

    context = PCAPContext(pcap_path, args.output)
    print(f"[*] Reading PCAP packets from {pcap_path.name}...")
    pkts = context.get_packets()
    print(f"[+] Loaded {len(pkts)} packets for plugin extraction.")
    collector = PCAPCollector()

    # Load enabled plugins from plugins.json
    plugins = {}
    if PLUGIN_FILE.exists():
        with open(PLUGIN_FILE, "r", encoding="utf-8") as f:
            plugins = json.load(f)

    for name, enabled in plugins.items():
        if not enabled:
            continue

        extractor_class = EXTRACTOR_MAP.get(name)
        if not extractor_class:
            print(f"[!] Unknown plugin: {name}")
            continue

        try:
            extractor = extractor_class(context)
            result = extractor.extract()
            collector.add(result)

            print(f"[{result['status']}] {result['artifact']}: {result['message']}")
        except Exception as e:
            failed_result = {
                "artifact": name,
                "status": "FAILED",
                "count": 0,
                "message": str(e)
            }
            collector.add(failed_result)
            print(f"[FAILED] {name}: {e}")

    summary = collector.summary()
    summary_file = PCAPMerger.write(summary, args.output)

    print(f"\nPCAP Summary written to: {summary_file}")
    print("PCAP Extraction Complete.")


if __name__ == "__main__":
    main()
