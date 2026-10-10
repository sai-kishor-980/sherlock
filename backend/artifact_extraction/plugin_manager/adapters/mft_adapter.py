import shutil
from pathlib import Path

from disk_image.analyzers.mft.analyzer import MFTAnalyzer


class MFTAdapter:

    def __init__(self, case_output):
        self.case_output = Path(case_output)

    def process(self, evidence):

        input_dir = (
            self.case_output /
            "mft_input"
        )

        output_dir = (
            self.case_output /
            "mft_analysis"
        )

        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        source = Path(evidence.path)

        if source.is_file():

            shutil.copy2(
                source,
                input_dir / source.name
            )

        elif source.is_dir():

            shutil.copytree(
                source,
                input_dir / source.name,
                dirs_exist_ok=True
            )

        else:
            raise FileNotFoundError(f"MFT evidence not found: {source}")

        analyzer = MFTAnalyzer(
            input_dir,
            output_dir
        )

        analyzer.analyze()

        return {
            "evidence_id": evidence.evidence_id,
            "name": evidence.name,
            "type": "mft",
            "status": "SUCCESS",
            "output": str(output_dir),
            "message": "MFT analysis completed."
        }
