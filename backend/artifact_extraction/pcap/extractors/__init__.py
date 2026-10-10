from .dns_extractor import DnsExtractor
from .http_extractor import HttpExtractor
from .tls_extractor import TlsExtractor
from .ip_stats_extractor import IpStatsExtractor
from .file_extractor import FileExtractor

EXTRACTOR_MAP = {
    "DnsExtractor": DnsExtractor,
    "HttpExtractor": HttpExtractor,
    "TlsExtractor": TlsExtractor,
    "IpStatsExtractor": IpStatsExtractor,
    "FileExtractor": FileExtractor
}

__all__ = [
    "DnsExtractor",
    "HttpExtractor",
    "TlsExtractor",
    "IpStatsExtractor",
    "FileExtractor",
    "EXTRACTOR_MAP"
]
