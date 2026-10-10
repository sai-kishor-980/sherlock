from abc import ABC, abstractmethod
from pathlib import Path


class BasePCAPExtractor(ABC):
    """
    Base class for all PCAP network packet extractors.
    """

    def __init__(self, context):
        self.context = context
        self.pcap_path = context.pcap_path
        self.output_dir = Path(context.output_dir)

    @abstractmethod
    def extract(self):
        """
        Execute packet extraction.
        Returns:
        {
            "artifact": str,
            "status": str,
            "count": int,
            "message": str,
            "data": list | dict
        }
        """
        pass

    def build_result(self, artifact, status, count=0, message="", data=None):
        return {
            "artifact": artifact,
            "status": status,
            "count": count,
            "message": message,
            "data": data or []
        }
