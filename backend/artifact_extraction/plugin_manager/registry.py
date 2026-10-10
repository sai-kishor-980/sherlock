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

    @classmethod
    def enabled(cls, plugin_name):

        if PLUGINS_FILE.exists():
            try:
                with open(PLUGINS_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    if plugin_name in config:
                        return bool(config[plugin_name])
            except Exception:
                pass

        plugin = cls.PLUGINS.get(plugin_name)

        if not plugin:
            return False

        return plugin["enabled"]