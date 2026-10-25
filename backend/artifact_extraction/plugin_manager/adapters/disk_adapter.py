import subprocess
import sys
from pathlib import Path


def _log_path_boundary(stage, value):
    print(
        f"[PATH] stage={stage} original={value!r} "
        f"type={type(value).__name__} cwd={str(Path.cwd())!r} "
        f"resolved={str(Path(value).resolve(strict=False))!r}",
        flush=True,
    )


class DiskAdapter:

    def __init__(self, case_output):

        self.case_output = Path(case_output)

    def process(self, evidence):

        _log_path_boundary("DiskAdapter evidence.path", evidence.path)

        output_dir = (
            self.case_output /
            "disk"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        disk_orchestrator = (
            Path(__file__).resolve().parents[2]
            / "disk_image"
            / "orchestrator.py"
        )

        command = [
            sys.executable,
            str(disk_orchestrator),
            evidence.path,
            "-o",
            str(output_dir)
        ]

        _log_path_boundary("DiskAdapter subprocess image argument", command[2])

        env = dict(**subprocess.os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        result = subprocess.run(
            command,
            cwd=str(disk_orchestrator.parent),
            env=env,
            capture_output=True,
            text=True
        )

        # Synchronize generated artifacts to extracted_artifacts/disk
        extracted_artifacts_disk = self.case_output / "extracted_artifacts" / "disk"
        extracted_artifacts_disk.mkdir(parents=True, exist_ok=True)

        for src_dir in [output_dir / "analyzed", output_dir / "filesystem", output_dir]:
            if src_dir.exists() and src_dir.is_dir():
                for json_file in src_dir.glob("*.json"):
                    dest = extracted_artifacts_disk / json_file.name
                    if not dest.exists():
                        import shutil
                        shutil.copy2(json_file, dest)

        if result.returncode != 0:

            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": "disk",
                "status": "FAILED",
                "output": str(output_dir),
                "message": result.stderr
            }

        return {
            "evidence_id": evidence.evidence_id,
            "name": evidence.name,
            "type": "disk",
            "status": "SUCCESS",
            "output": str(output_dir),
            "message": "Disk analysis completed."
        }