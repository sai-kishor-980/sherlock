import sys
from pathlib import Path


PLUGIN_MANAGER_ROOT = Path(__file__).resolve().parent

PROJECT_ROOT = PLUGIN_MANAGER_ROOT.parent.parent

ARTIFACT_EXTRACTION_ROOT = PLUGIN_MANAGER_ROOT.parent

# Ensure roots are in sys.path for adapters importing disk_image/memory/pcap modules
for root in [str(PROJECT_ROOT), str(ARTIFACT_EXTRACTION_ROOT)]:
    if root not in sys.path:
        sys.path.insert(0, root)

OUTPUT_ROOT = PROJECT_ROOT / "output" / "cases"

EVIDENCE_FILE = PLUGIN_MANAGER_ROOT / "evidence.json"

PLUGINS_FILE = PLUGIN_MANAGER_ROOT / "plugins.json"