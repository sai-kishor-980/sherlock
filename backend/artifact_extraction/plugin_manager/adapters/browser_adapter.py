import shutil
from pathlib import Path

from disk_image.analyzers.browser.analyzer import BrowserAnalyzer


class BrowserAdapter:

    def __init__(self, case_output):

        self.case_output = Path(case_output)

    def process(self, evidence):

        input_dir = (
            self.case_output /
            "browser_input"
        )

        output_dir = (
            self.case_output /
            "browser_analysis"
        )

        input_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        source = Path(evidence.path)

        if source.is_file():

            shutil.copy2(
                source,
                input_dir / source.name
            )

        elif source.is_dir():

            destination = input_dir / source.name

            shutil.copytree(
                source,
                destination,
                dirs_exist_ok=True
            )

        else:

            raise FileNotFoundError(
                f"Browser evidence not found: {source}"
            )

        analyzer = BrowserAnalyzer(
            input_dir,
            output_dir
        )

        analyzer.analyze()

        return {
            "evidence_id": evidence.evidence_id,
            "name": evidence.name,
            "type": "browser",
            "status": "SUCCESS",
            "output": str(output_dir),
            "message": "Browser analysis completed."
        }