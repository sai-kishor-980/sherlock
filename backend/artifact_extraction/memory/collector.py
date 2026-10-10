import json
from pathlib import Path

from config import PLUGIN_OUTPUT_DIR


class ArtifactCollector:
    """
    Collects raw Volatility plugin JSON results.

    The collector groups plugin output into logical
    SherlockGPT memory artifact categories.
    """

    PLUGIN_MAP = {

        "system": [
            "windows.info"
        ],

        "processes": [
            "windows.pslist",
            "windows.psscan",
            "windows.pstree"
        ],

        "execution": [
            "windows.cmdline"
        ],

        "network": [],

        "modules": [
            "windows.dlllist",
            "windows.modules",
            "windows.modscan"
        ],

        "memory_analysis": [
            "windows.vadinfo"
        ],

        "users_security": [
            "windows.sessions",
            "windows.getsids",
            "windows.privileges"
        ],

        "services_persistence": [
            "windows.svcscan",
            "windows.scheduled_tasks"
        ],

        "threat_hunting": [
            "windows.malfind"
        ],

        "handles": [
            "windows.handles",
            "windows.filescan"
        ]
    }

    def __init__(self, output_dir=None):

        self.output_dir = (
            Path(output_dir) / "plugins"
            if output_dir
            else PLUGIN_OUTPUT_DIR
        )

    # =========================================================
    # HELPERS
    # =========================================================

    @staticmethod
    def plugin_filename(plugin):

        return (
            plugin
            .replace(".", "_")
            .replace("-", "_")
            + ".json"
        )

    # =========================================================
    # COLLECT
    # =========================================================

    def collect(self):

        grouped = {}

        for category, plugins in self.PLUGIN_MAP.items():

            grouped[category] = {}

            for plugin in plugins:

                filename = self.plugin_filename(
                    plugin
                )

                file_path = (
                    self.output_dir
                    / filename
                )

                if not file_path.exists():

                    continue

                try:

                    with open(
                        file_path,
                        "r",
                        encoding="utf-8"
                    ) as file:

                        grouped[category][plugin] = (
                            json.load(file)
                        )

                except Exception as error:

                    grouped[category][plugin] = {
                        "collection_error": str(error)
                    }

        return grouped


if __name__ == "__main__":

    collector = ArtifactCollector()

    data = collector.collect()

    for category, plugins in data.items():

        print(
            f"\n{category.upper()}"
        )

        for plugin in plugins:

            print(
                f"  ✓ {plugin}"
            )