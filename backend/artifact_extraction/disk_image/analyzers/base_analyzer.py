import json
from pathlib import Path


class BaseAnalyzer:
    """
    Base class for all disk image artifact analyzers.
    """

    def __init__(self, extracted_data_dir, output_dir):
        """
        :param extracted_data_dir: Path where raw artifacts were extracted (e.g. output/registry)
        :param output_dir: Path where analysis JSON results should be written (e.g. output/analyzed)
        """
        self.extracted_data_dir = Path(extracted_data_dir)
        self.output_dir = Path(output_dir)
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self):
        """
        Perform analysis on extracted artifacts.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Analyzers must implement the analyze() method.")

    def write_json(self, filename, data):
        """
        Helper method to write analysis results to JSON.
        """
        output_file = self.output_dir / filename
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        return output_file
