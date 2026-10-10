import shutil
from pathlib import Path

from disk_image.analyzers.prefetch.analyzer import PrefetchAnalyzer


class PrefetchAdapter:

    def __init__(self, case_output):
        self.case_output = Path(case_output)

    def process(self, evidence):

        input_dir = (
            self.case_output /
            "prefetch_input"
        )

        output_dir = (
            self.case_output /
            "prefetch_analysis"
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
            raise FileNotFoundError(f"Prefetch evidence not found: {source}")

        analyzer = PrefetchAnalyzer(
            input_dir,
            output_dir
        )

        analyzer.analyze()

        return {
            "evidence_id": evidence.evidence_id,
            "name": evidence.name,
            "type": "prefetch",
            "status": "SUCCESS",
            "output": str(output_dir),
            "message": "Prefetch analysis completed."
        }
