from pathlib import Path
# PROJECT PATHS

PROJECT_ROOT = Path(r"C:/Users/saiki/Desktop/BTECH/ForensicAI/project/prot1-main")

VOLATILITY_PATH = PROJECT_ROOT / "tools" / "volatility3"
VOLATILITY_SCRIPT = VOLATILITY_PATH / "vol.py"

# OUTPUT PATHS

OUTPUT_DIR = (
    PROJECT_ROOT
    / "artifact_extraction"
    / "memory"
    / "output"
)
PLUGIN_OUTPUT_DIR = OUTPUT_DIR / "plugins"
FINAL_OUTPUT_DIR = OUTPUT_DIR / "final"

LOG_DIR = (
    PROJECT_ROOT
    / "artifact_extraction"
    / "memory"
    / "logs"
)

#CONFIGURATION
PLUGIN_FILE = (
    PROJECT_ROOT
    / "artifact_extraction"
    / "memory"
    / "plugins.json"
)


# EXECUTION
# Number of Volatility processes allowed to run simultaneously.
#
# Start conservatively because several Volatility processes
# reading the same RAM image can consume significant resources.
MAX_WORKERS = 1

VOLATILITY_RENDERER = "json"