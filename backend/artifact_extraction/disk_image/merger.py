import json
import os


class Merger:
    """
    Writes the extraction summary to disk.
    """

    @staticmethod
    def write(summary, output_directory):

        os.makedirs(output_directory, exist_ok=True)

        output_file = os.path.join(
            output_directory,
            "summary.json"
        )

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(
                summary,
                f,
                indent=4
            )

        return output_file