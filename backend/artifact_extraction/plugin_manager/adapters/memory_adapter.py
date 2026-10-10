import subprocess
import sys
from pathlib import Path


class MemoryAdapter:

    def __init__(self, case_output):
        self.case_output = Path(case_output)

    def process(self, evidence):

        output_dir = (
            self.case_output
            / "memory"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        # --------------------------------------------------
        # Memory evidence path
        # --------------------------------------------------

        memory_image = Path(evidence.path).resolve()

        if not memory_image.exists():
            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": "memory",
                "status": "FAILED",
                "output": str(output_dir),
                "message": (
                    f"Memory image not found: {memory_image}"
                )
            }

        # --------------------------------------------------
        # Memory orchestrator
        # --------------------------------------------------

        orchestrator = (
            Path(__file__).resolve().parents[2]
            / "memory"
            / "orchestrator.py"
        )

        if not orchestrator.exists():
            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": "memory",
                "status": "FAILED",
                "output": str(output_dir),
                "message": (
                    f"Memory orchestrator not found: {orchestrator}"
                )
            }

        # --------------------------------------------------
        # Execute memory analysis
        # --------------------------------------------------

        command = [
            sys.executable,
            str(orchestrator),
            str(memory_image),
            "-o",
            str(output_dir)
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        # --------------------------------------------------
        # Failure
        # --------------------------------------------------

        if result.returncode != 0:

            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": "memory",
                "status": "FAILED",
                "output": str(output_dir),
                "message": (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "Memory analysis failed."
                )
            }

        # --------------------------------------------------
        # Success
        # --------------------------------------------------

        return {
            "evidence_id": evidence.evidence_id,
            "name": evidence.name,
            "type": "memory",
            "status": "SUCCESS",
            "output": str(output_dir),
            "message": "Memory analysis completed."
        }