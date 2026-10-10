import json
import logging
import os
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from config import (
    VOLATILITY_PATH,
    VOLATILITY_SCRIPT,
    PLUGIN_OUTPUT_DIR,
    PLUGIN_FILE,
    MAX_WORKERS,
    VOLATILITY_RENDERER,
    LOG_DIR,
)


LOGGER = logging.getLogger("forensicai.volatility")
LOG_DIR.mkdir(parents=True, exist_ok=True)
if not LOGGER.handlers:
    handler = logging.FileHandler(
        LOG_DIR / "volatility_plugins.log",
        encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)

LOCK_FILE = LOG_DIR / "volatility_plugins.lock"


@contextmanager
def volatility_process_lock():
    with open(LOCK_FILE, "a+b") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            lock_file.write(b"0")
            lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class PluginOrchestrator:
    """
    Executes the configured Volatility plugins against a RAM image.

    This class is responsible ONLY for plugin execution.

    It does not perform:
        - merging
        - normalization
        - summaries
        - frontend handling
    """

    def __init__(self, memory_image=None, output_dir=None):

        self.memory_image = Path(memory_image) if memory_image else None
        self.plugin_output_dir = (
            Path(output_dir) / "plugins"
            if output_dir
            else PLUGIN_OUTPUT_DIR
        )

        self.plugin_output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(PLUGIN_FILE, "r", encoding="utf-8") as file:
            config = json.load(file)

        self.plugin_groups = config.get(
            "memory_plugins",
            {}
        )

        self.plugins = self._flatten_plugins()

        self.results = {}
        self.failures = {}

    # =========================================================
    # PLUGIN CONFIGURATION
    # =========================================================

    def _flatten_plugins(self) -> List[str]:
        """
        Convert category-based configuration into a unique
        plugin list.
        """

        plugins = []

        for group_plugins in self.plugin_groups.values():

            for plugin in group_plugins:

                if plugin not in plugins:
                    plugins.append(plugin)

        return plugins

    # =========================================================
    # VALIDATION
    # =========================================================

    def validate(self):

        if not self.memory_image:
            raise ValueError(
                "No memory image was provided."
            )

        if not self.memory_image.exists():
            raise FileNotFoundError(
                f"Memory image not found: {self.memory_image}"
            )

        if not VOLATILITY_SCRIPT.exists():
            raise FileNotFoundError(
                f"Volatility script not found: {VOLATILITY_SCRIPT}"
            )

    # =========================================================
    # OUTPUT NAME
    # =========================================================

    @staticmethod
    def _output_name(plugin: str) -> str:

        return (
            plugin
            .replace(".", "_")
            .replace("-", "_")
        )

    # =========================================================
    # RUN SINGLE PLUGIN
    # =========================================================

    def run_plugin(self, plugin: str) -> Dict:

        output_file = (
            self.plugin_output_dir
            / f"{self._output_name(plugin)}.json"
        )

        command = [
            "python",
            str(VOLATILITY_SCRIPT),
            "-f",
            str(self.memory_image),
            "-r",
            VOLATILITY_RENDERER,
            "-q",
            plugin,
        ]

        start_time = datetime.now().isoformat()
        process_id = os.getpid()
        thread_id = threading.get_ident()
        command_text = subprocess.list2cmdline(command)

        print(f"[MEMORY] Running {plugin}")
        LOGGER.info(
            "plugin=%s pid=%s tid=%s start=%s command=%s",
            plugin,
            process_id,
            thread_id,
            start_time,
            command_text,
        )

        try:
            with volatility_process_lock():
                result = subprocess.run(
                    command,
                    cwd=VOLATILITY_PATH,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )

            end_time = datetime.now().isoformat()
            LOGGER.info(
                "plugin=%s pid=%s tid=%s end=%s exit_code=%s stderr=%s stdout=%s",
                plugin,
                process_id,
                thread_id,
                end_time,
                result.returncode,
                result.stderr.strip(),
                result.stdout.strip(),
            )

            if result.returncode != 0:

                error = {
                    "plugin": plugin,
                    "status": "failed",
                    "error": result.stderr.strip()
                }

                print(
                    f"[FAILED] {plugin}: "
                    f"{result.stderr.strip()}"
                )

                return error

            # Validate that stdout actually contains JSON.
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError:

                error = {
                    "plugin": plugin,
                    "status": "failed",
                    "error": (
                        "Volatility returned invalid JSON."
                    ),
                    "stdout_preview": result.stdout[:1000]
                }

                return error

            # Preserve the raw plugin result.
            with open(
                output_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    parsed,
                    file,
                    indent=4
                )

            print(
                f"[SUCCESS] {plugin} "
                f"-> {output_file.name}"
            )

            return {
                "plugin": plugin,
                "status": "success",
                "output_file": str(output_file),
                "data": parsed
            }

        except Exception as error:
            LOGGER.info(
                "plugin=%s pid=%s tid=%s end=%s exit_code=%s stderr=%s stdout=%s",
                plugin,
                process_id,
                thread_id,
                datetime.now().isoformat(),
                "not-started",
                str(error),
                "",
            )

            return {
                "plugin": plugin,
                "status": "failed",
                "error": str(error)
            }

    # =========================================================
    # RUN ALL
    # =========================================================

    def run_all(self):

        self.validate()

        print("=" * 70)
        print("MEMORY FORENSIC ANALYSIS")
        print("=" * 70)

        print(
            f"RAM Image : {self.memory_image}"
        )

        print(
            f"Plugins   : {len(self.plugins)}"
        )

        print(
            f"Workers   : {MAX_WORKERS}"
        )

        print("=" * 70)

        for plugin in self.plugins:
            try:
                result = self.run_plugin(plugin)

                if result["status"] == "success":
                    self.results[plugin] = result
                else:
                    self.failures[plugin] = result

            except Exception as error:
                self.failures[plugin] = {
                    "plugin": plugin,
                    "status": "failed",
                    "error": str(error)
                }

        print("\nMemory plugin execution completed.")

        print(
            f"Successful : {len(self.results)}"
        )

        print(
            f"Failed     : {len(self.failures)}"
        )

        return {
            "successful": self.results,
            "failed": self.failures
        }


if __name__ == "__main__":

    orchestrator = PluginOrchestrator()

    orchestrator.run_all()