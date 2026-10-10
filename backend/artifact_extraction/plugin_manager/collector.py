from datetime import datetime


class PluginCollector:

    def __init__(self, case_id=None):
        self.case_id = case_id
        self.started = datetime.now().isoformat()
        self.results = []


    def add(self, result):
        self.results.append(result)

    def summary(self):

        successful = 0
        failed = 0
        skipped = 0

        for result in self.results:

            status = result.get("status")

            if status == "SUCCESS":
                successful += 1

            elif status == "FAILED":
                failed += 1

            elif status == "SKIPPED":
                skipped += 1

        return {
            "case_id": self.case_id,
            "started": self.started,
            "finished": datetime.now().isoformat(),

            "total_evidence": len(self.results),

            "successful": successful,
            "failed": failed,
            "skipped": skipped,

            "evidence": self.results
        }