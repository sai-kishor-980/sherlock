import os
import re
from pathlib import Path
from .base_extractor import BasePCAPExtractor

try:
    from scapy.all import rdpcap, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class FileExtractor(BasePCAPExtractor):
    """
    Carves transferred files or HTTP payloads from PCAP packets.
    """

    def extract(self):
        if not SCAPY_AVAILABLE:
            return self.build_result(
                artifact="File_Carver",
                status="FAILED",
                message="Scapy is not installed."
            )

        carved_dir = self.output_dir / "carved_files"
        carved_dir.mkdir(parents=True, exist_ok=True)

        carved_files = []
        try:
            packets = rdpcap(str(self.pcap_path))
            file_counter = 0

            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    payload = pkt[Raw].load

                    # Look for HTTP response with 200 OK and file payloads
                    if payload.startswith(b"HTTP/1.") and b"200 OK" in payload:
                        # Extract headers vs body
                        parts = payload.split(b"\r\n\r\n", 1)
                        if len(parts) == 2:
                            headers, body = parts
                            headers_str = headers.decode("utf-8", errors="ignore")

                            # Find Content-Type or Content-Disposition filename
                            filename = f"carved_file_{file_counter}.bin"
                            fn_match = re.search(r'filename="?([^";\r\n]+)"?', headers_str, re.IGNORECASE)
                            if fn_match:
                                filename = fn_match.group(1).strip()

                            if len(body) > 0:
                                out_file = carved_dir / filename
                                with open(out_file, "wb") as f:
                                    f.write(body)

                                carved_files.append({
                                    "filename": filename,
                                    "saved_path": str(out_file),
                                    "size_bytes": len(body)
                                })
                                file_counter += 1

            status = "SUCCESS" if carved_files else "SKIPPED"
            return self.build_result(
                artifact="File_Carver",
                status=status,
                count=len(carved_files),
                message=f"Carved {len(carved_files)} files from PCAP.",
                data=carved_files
            )
        except Exception as e:
            return self.build_result(
                artifact="File_Carver",
                status="FAILED",
                message=f"Error reading PCAP: {e}"
            )
