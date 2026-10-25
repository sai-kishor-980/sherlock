from pathlib import Path


class EvidenceDetector:

    EXTENSION_MAP = {
        # Disk
        ".e01": "disk",
        ".ex01": "disk",
        ".raw": "disk",
        ".img": "disk",
        ".dd": "disk",
        ".001": "disk",
        ".bin": "disk",

        # Memory
        ".mem": "memory",
        ".dmp": "memory",
        ".vmem": "memory",

        # PCAP
        ".pcap": "pcap",
        ".pcapng": "pcap",

        # Event logs
        ".evtx": "eventlog",

        # LNK
        ".lnk": "lnk",

        # Prefetch
        ".pf": "prefetch",

        # Email
        ".eml": "email",
        ".msg": "email",
        ".mbox": "email",

        # Jump Lists
        ".automaticdestinations-ms": "jumplist",
        ".customdestinations-ms": "jumplist",

        # MFT
        ".mft": "mft",
    }

    @classmethod
    def detect(cls, path, check_exists=False):

        path = Path(path)

        if check_exists and not path.exists():
            raise FileNotFoundError(
                f"Evidence not found: {path}"
            )

        name_lower = path.name.lower()

        if name_lower == "$mft":
            return "mft"

        if name_lower.startswith("$i") or name_lower.startswith("$r") or name_lower == "$recycle.bin":
            return "recyclebin"

        if name_lower in ["sam", "system", "software", "security", "ntuser.dat"]:
            return "registry"

        suffix = path.suffix.lower()
        if suffix in [".reg"]:
            return "registry"

        if suffix in cls.EXTENSION_MAP:
            return cls.EXTENSION_MAP[suffix]

        return "unknown"