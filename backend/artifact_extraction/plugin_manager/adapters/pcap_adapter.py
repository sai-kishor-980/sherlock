import subprocess
import sys
from pathlib import Path


class PCAPAdapter:

    def __init__(self, case_output):

        self.case_output = Path(case_output)

    def process(self, evidence):

        output_dir = (
            self.case_output /
            "pcap"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        orchestrator = (
            Path(__file__).resolve().parents[2]
            / "pcap"
            / "orchestrator.py"
        )

        command = [
            sys.executable,
            str(orchestrator),
            evidence.path,
            "-o",
            str(output_dir)
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:

            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": "pcap",
                "status": "FAILED",
                "message": result.stderr
            }

        return {
            "evidence_id": evidence.evidence_id,
            "name": evidence.name,
            "type": "pcap",
            "status": "SUCCESS",
            "output": str(output_dir),
            "message": "PCAP analysis completed."
        }