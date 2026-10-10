import json
from datetime import datetime, timezone
from pathlib import Path

from config import FINAL_OUTPUT_DIR


class ArtifactMerger:
    """
    Converts raw Volatility plugin results into logical
    SherlockGPT memory artifact files.
    """

    def __init__(
        self,
        collected_data,
        execution_results=None,
        output_dir=None
    ):

        self.collected_data = collected_data

        self.execution_results = (
            execution_results or {}
        )

        self.final_output_dir = (
            Path(output_dir)
            if output_dir
            else FINAL_OUTPUT_DIR
        )

        self.final_output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    # =========================================================
    # SAVE
    # =========================================================

    def save(self):

        saved_files = []

        for category, data in self.collected_data.items():

            if not data:
                continue

            output_file = (
                self.final_output_dir
                / f"{category}.json"
            )

            payload = {
                "artifact_type": category,
                "generated_at": self._timestamp(),
                "plugins": data
            }

            self._write_json(
                output_file,
                payload
            )

            saved_files.append(
                output_file
            )

        summary = self._build_summary()

        summary_file = (
            self.final_output_dir
            / "memory_summary.json"
        )

        self._write_json(
            summary_file,
            summary
        )

        saved_files.append(
            summary_file
        )

        return saved_files

    # =========================================================
    # SUMMARY
    # =========================================================

    def _build_summary(self):

        successful = self.execution_results.get(
            "successful",
            {}
        )

        failed = self.execution_results.get(
            "failed",
            {}
        )

        categories = {}

        for category, data in self.collected_data.items():

            categories[category] = {
                "status": (
                    "completed"
                    if data
                    else "not_available"
                ),
                "plugins": list(
                    data.keys()
                )
            }

        return {
            "artifact_type": "memory",
            "status": (
                "completed"
                if successful
                else "failed"
            ),
            "generated_at": self._timestamp(),

            "execution": {
                "total_plugins": (
                    len(successful)
                    + len(failed)
                ),
                "successful": len(successful),
                "failed": len(failed)
            },

            "categories": categories,

            "failed_plugins": {
                plugin: result
                for plugin, result
                in failed.items()
            }
        }

    # =========================================================
    # WRITE JSON
    # =========================================================

    @staticmethod
    def _write_json(
        output_file,
        data
    ):

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4,
                default=str
            )

        print(
            f"[OUTPUT] {output_file.name}"
        )

    # =========================================================
    # TIMESTAMP
    # =========================================================

    @staticmethod
    def _timestamp():

        return datetime.now(
            timezone.utc
        ).isoformat()