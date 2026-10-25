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

        # Also emit standard contract files for Supervisor and Network Agent
        for art in summary.get("artifacts", []):
            art_name = art.get("artifact", "").lower()
            if art_name == "dns":
                dns_file = out_path / "dns_analysis.json"
                with open(dns_file, "w", encoding="utf-8") as f:
                    json.dump({
                        "meta": {
                            "domain": "network",
                            "contract_file": "dns_analysis.json"
                        },
                        "records": art.get("data", []),
                        "summary": {
                            "total_records": art.get("count", 0),
                            "status": art.get("status")
                        }
                    }, f, indent=4)
            elif art_name == "ip_stats":
                conn_file = out_path / "network_connections.json"
                data = art.get("data", {})
                convs = data.get("conversations", []) if isinstance(data, dict) else []
                with open(conn_file, "w", encoding="utf-8") as f:
                    json.dump({
                        "meta": {
                            "domain": "network",
                            "contract_file": "network_connections.json"
                        },
                        "records": convs,
                        "summary": {
                            "total_records": len(convs),
                            "status": art.get("status")
                        }
                    }, f, indent=4)

        return output_file
