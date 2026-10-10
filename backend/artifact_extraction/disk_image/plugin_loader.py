import json
from pathlib import Path

from extractors.registry.extractor import RegistryExtractor
from extractors.browser.extractor import BrowserExtractor
from extractors.eventlog.extractor import EventLogExtractor
from extractors.prefetch.extractor import PrefetchExtractor
from extractors.recyclebin.extractor import RecycleBinExtractor
from extractors.lnk.extractor import LnkExtractor
from extractors.jumplist.extractor import JumpListExtractor
from extractors.mft.extractor import MFTExtractor
from extractors.email.extractor import EmailExtractor


EXTRACTOR_MAP = {
    "RegistryExtractor": RegistryExtractor,
    "BrowserExtractor": BrowserExtractor,
    "EventLogExtractor": EventLogExtractor,
    "PrefetchExtractor": PrefetchExtractor,
    "RecycleBinExtractor": RecycleBinExtractor,
    "LnkExtractor": LnkExtractor,
    "JumpListExtractor": JumpListExtractor,
    "MFTExtractor": MFTExtractor,
    "EmailExtractor": EmailExtractor,
}


class PluginLoader:

    def __init__(self, plugin_file=None):

        if plugin_file is None:
            plugin_file = (
                Path(__file__).resolve().parent /
                "plugins.json"
            )

        self.plugin_file = Path(plugin_file)

    def load(self, context):

        if not self.plugin_file.exists():
            raise FileNotFoundError(
                f"Plugin configuration not found: "
                f"{self.plugin_file}"
            )

        with open(
            self.plugin_file,
            "r",
            encoding="utf-8"
        ) as f:

            plugins = json.load(f)

        extractors = []

        for name, enabled in plugins.items():

            if not enabled:
                continue

            extractor_class = EXTRACTOR_MAP.get(name)

            if extractor_class is None:
                print(
                    f"[!] Unknown disk plugin: {name}"
                )
                continue

            extractors.append(
                extractor_class(context)
            )

        return extractors