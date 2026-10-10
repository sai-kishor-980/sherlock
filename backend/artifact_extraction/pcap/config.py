from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DEFAULT_OUTPUT_DIR = BASE_DIR / "output"

PLUGIN_OUTPUT_DIR = DEFAULT_OUTPUT_DIR / "plugins"

ANALYZED_OUTPUT_DIR = DEFAULT_OUTPUT_DIR / "analyzed"

LOG_DIR = DEFAULT_OUTPUT_DIR / "logs"

PLUGIN_FILE = BASE_DIR / "plugins.json"