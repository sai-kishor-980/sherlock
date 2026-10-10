import json
import uuid
from pathlib import Path

from models import Evidence, Case
from detector import EvidenceDetector
from registry import PluginRegistry
from executor import PluginExecutor
from collector import PluginCollector
from config import EVIDENCE_FILE, OUTPUT_ROOT

from adapters.disk_adapter import DiskAdapter
from adapters.memory_adapter import MemoryAdapter
from adapters.pcap_adapter import PCAPAdapter
from adapters.browser_adapter import BrowserAdapter
from adapters.email_adapter import EmailAdapter
from adapters.registry_adapter import RegistryAdapter
from adapters.eventlog_adapter import EventLogAdapter
from adapters.lnk_adapter import LnkAdapter
from adapters.mft_adapter import MFTAdapter
from adapters.prefetch_adapter import PrefetchAdapter
from adapters.recyclebin_adapter import RecycleBinAdapter
from adapters.jumplist_adapter import JumpListAdapter


def _log_path_boundary(stage, value):
    print(
        f"[PATH] stage={stage} original={value!r} "
        f"type={type(value).__name__} cwd={str(Path.cwd())!r} "
        f"resolved={str(Path(value).resolve(strict=False))!r}",
        flush=True,
    )


class PluginManager:

    def __init__(self, max_workers=8, case_id=None):

        self.max_workers = max_workers
        self.case_id = case_id
        if self.case_id:
            self.case_output = OUTPUT_ROOT / self.case_id
            self.case_output.mkdir(parents=True, exist_ok=True)
            self.collector = PluginCollector(case_id=self.case_id)
            self.adapters = self._build_adapters(self.case_output)
        else:
            self.case_output = None
            self.collector = None
            self.adapters = None

    def _build_adapters(self, case_output):
        return {
            "disk": DiskAdapter(case_output),
            "memory": MemoryAdapter(case_output),
            "pcap": PCAPAdapter(case_output),

            "browser": BrowserAdapter(case_output),
            "email": EmailAdapter(case_output),
            "registry": RegistryAdapter(case_output),
            "eventlog": EventLogAdapter(case_output),
            "lnk": LnkAdapter(case_output),

            "mft": MFTAdapter(case_output),
            "prefetch": PrefetchAdapter(case_output),
            "recyclebin": RecycleBinAdapter(case_output),
            "jumplist": JumpListAdapter(case_output),
        }

    def create_case(self, case_id=None):

        target_id = (
            case_id
            or self.case_id
            or ("CASE-" + uuid.uuid4().hex[:8].upper())
        )
        self.case_id = target_id
        self.case_output = OUTPUT_ROOT / self.case_id
        self.case_output.mkdir(parents=True, exist_ok=True)
        self.collector = PluginCollector(case_id=self.case_id)
        self.adapters = self._build_adapters(self.case_output)

        return Case(case_id=self.case_id, evidence=[])

    def register_evidence(self, case, evidence_list):

        start_idx = len(case.evidence) + 1

        for index, item in enumerate(evidence_list, start=start_idx):

            if isinstance(item, Evidence):
                path = item.path
                explicit_type = item.evidence_type
                name = item.name
                explicit_id = item.evidence_id
            else:
                path = item["path"]
                _log_path_boundary("json evidence item", path)
                explicit_type = item.get("type")
                name = item.get("name", Path(path).name)
                explicit_id = item.get("evidence_id") or item.get("id")

            if explicit_type:
                evidence_type = explicit_type
            else:
                evidence_type = EvidenceDetector.detect(path)

            if not PluginRegistry.enabled(evidence_type):
                print(
                    f"[SKIPPED] Plugin disabled: {evidence_type} for {path}"
                )
                continue

            evidence = Evidence(
                evidence_id=explicit_id or f"EVD-{index:03d}",
                path=path,
                evidence_type=evidence_type,
                file_format=Path(path).suffix.lower(),
                name=name
            )

            _log_path_boundary("registered Evidence.path", evidence.path)

            case.evidence.append(evidence)

        return case.evidence

    def execute_case(self, case):

        print("=" * 70)
        print("SHERLOCK PLUGIN MANAGER - EXECUTING CASE")
        print("=" * 70)
        print(f"Case ID: {case.case_id}")
        print(f"Registered Evidence Items: {len(case.evidence)}")

        for item in case.evidence:
            print(
                f"  {item.evidence_id} | "
                f"{item.evidence_type} | "
                f"{item.name}"
            )

        print("\nStarting execution...\n")

        executor = PluginExecutor(self.adapters)
        results = executor.execute_all(case.evidence)

        for result in results:
            self.collector.add(result)
            print(
                f"[{result['status']}] "
                f"{result['type']} | "
                f"{result['name']}"
            )

        summary = self.collector.summary()
        summary_file = self.save_case_summary(summary)

        print("\n" + "=" * 70)
        print("CASE PROCESSING COMPLETE")
        print("=" * 70)
        print(f"Summary: {summary_file}")

        return summary

    def load_evidence(self):

        if not EVIDENCE_FILE.exists():
            print(f"[-] Evidence file not found: {EVIDENCE_FILE}")
            return []

        with open(EVIDENCE_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)

        for item in config.get("evidence", []):
            _log_path_boundary(
                "evidence loader JSON item",
                item.get("path"),
            )

        case = self.create_case(self.case_id)
        self.register_evidence(case, config.get("evidence", []))
        return case.evidence

    def save_case_summary(self, summary):

        case_file = (
            self.case_output /
            "case_summary.json"
        )

        with open(
            case_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                {
                    "case_id": self.case_id,
                    **summary
                },
                f,
                indent=4
            )

        return case_file

    def run(self):

        print("=" * 70)
        print("SHERLOCK PLUGIN MANAGER")
        print("=" * 70)

        case_id = self.case_id
        config = {}

        if EVIDENCE_FILE.exists():
            try:
                with open(EVIDENCE_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                for item in config.get("evidence", []):
                    _log_path_boundary(
                        "case loader JSON evidence",
                        item.get("path"),
                    )
                case_id = (
                    config.get("case_id") or
                    config.get("case_name") or
                    self.case_id
                )
            except Exception:
                config = {}

        case = self.create_case(case_id)

        if config.get("evidence"):
            self.register_evidence(case, config.get("evidence", []))

        return self.execute_case(case)



if __name__ == "__main__":

    manager = PluginManager()
    manager.run()