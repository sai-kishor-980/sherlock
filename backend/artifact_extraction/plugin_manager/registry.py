import json
from config import PLUGINS_FILE


class PluginRegistry:

    PLUGINS = {
        "disk": {
            "enabled": True,
            "mode": "container",
            "adapter": "disk"
        },

        "memory": {
            "enabled": True,
            "mode": "standalone",
            "adapter": "memory"
        },

        "pcap": {
            "enabled": True,
            "mode": "standalone",
            "adapter": "pcap"
        },

        "browser": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "browser"
        },

        "email": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "email"
        },

        "registry": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "registry"
        },

        "eventlog": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "eventlog"
        },

        "jumplist": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "jumplist"
        },

        "lnk": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "lnk"
        },

        "mft": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "mft"
        },

        "prefetch": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "prefetch"
        },

        "recyclebin": {
            "enabled": True,
            "mode": "artifact",
            "adapter": "recyclebin"
        }
    }

    ALIAS_MAP = {
        "pcap": "pcap",
        "pcapng": "pcap",
        "network": "pcap",
        "net": "pcap",
        "packet": "pcap",

        "disk": "disk",
        "e01": "disk",
        "ex01": "disk",
        "raw": "disk",
        "img": "disk",
        "dd": "disk",
        "001": "disk",
        "bin": "disk",

        "memory": "memory",
        "mem": "memory",
        "dmp": "memory",
        "vmem": "memory",
        "ram": "memory",

        "eventlog": "eventlog",
        "evtx": "eventlog",
        "logs": "eventlog",
        "log": "eventlog",
        "sysmon": "eventlog",

        "registry": "registry",
        "reg": "registry",
        "hive": "registry",

        "browser": "browser",
        "chrome": "browser",
        "firefox": "browser",
        "edge": "browser",
        "history": "browser",

        "email": "email",
        "eml": "email",
        "msg": "email",
        "mbox": "email",

        "lnk": "lnk",
        "shortcut": "lnk",

        "mft": "mft",
        "$mft": "mft",

        "prefetch": "prefetch",
        "pf": "prefetch",

        "recyclebin": "recyclebin",
        "trash": "recyclebin",

        "jumplist": "jumplist",
        "destinations-ms": "jumplist",
    }

    @classmethod
    def canonicalize(cls, name):
        if not name:
            return ""
        clean = str(name).strip().lower().lstrip(".")
        return cls.ALIAS_MAP.get(clean, clean)

    @classmethod
    def enabled(cls, plugin_name):
        canonical = cls.canonicalize(plugin_name)

        if PLUGINS_FILE.exists():
            try:
                with open(PLUGINS_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    if canonical in config:
                        return bool(config[canonical])
                    # Try raw lowercase
                    raw_low = str(plugin_name).strip().lower()
                    if raw_low in config:
                        return bool(config[raw_low])
            except Exception:
                pass

        plugin = cls.PLUGINS.get(canonical) or cls.PLUGINS.get(str(plugin_name).strip().lower())

        if not plugin:
            return False

        return plugin["enabled"]