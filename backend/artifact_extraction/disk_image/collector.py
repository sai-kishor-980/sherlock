from datetime import datetime


class Collector:
    """
    Collects extraction results from all extractors.
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
        total_files = 0

        for result in self.results:

            status = result.get("status", "")

            if status == "SUCCESS":
                success += 1

            elif status == "SKIPPED":
                skipped += 1

            elif status == "FAILED":
                failed += 1

            total_files += result.get("files", 0)

        return {
            "started": self.started,
            "finished": datetime.now().isoformat(),
            "successful_extractors": success,
            "skipped_extractors": skipped,
            "failed_extractors": failed,
            "total_files": total_files,
            "artifacts": self.results
        }