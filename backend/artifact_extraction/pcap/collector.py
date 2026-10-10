from datetime import datetime


class PCAPCollector:
    """
    Collects extraction results from all PCAP extractors.
    """

    def __init__(self):
        self.results = []
        self.started = datetime.now().isoformat()

    def add(self, result):
        self.results.append(result)

    def summary(self):
        success = 0
        skipped = 0
        failed = 0
        total_items = 0

        for result in self.results:
            status = result.get("status", "")
            if status == "SUCCESS":
                success += 1
            elif status == "SKIPPED":
                skipped += 1
            elif status == "FAILED":
                failed += 1
            total_items += result.get("count", 0)

        return {
            "started": self.started,
            "finished": datetime.now().isoformat(),
            "successful_extractors": success,
            "skipped_extractors": skipped,
            "failed_extractors": failed,
            "total_items_extracted": total_items,
            "artifacts": self.results
        }
