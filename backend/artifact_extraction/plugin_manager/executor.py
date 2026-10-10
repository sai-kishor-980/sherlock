from concurrent.futures import ThreadPoolExecutor, as_completed


class PluginExecutor:

    def __init__(self, adapters):
        self.adapters = adapters

    def execute_one(self, evidence):

        evidence_type = evidence.evidence_type

        adapter = self.adapters.get(evidence_type)

        if adapter is None:

            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": evidence_type,
                "status": "FAILED",
                "message": f"No adapter available for {evidence_type}"
            }

        try:

            result = adapter.process(evidence)

            return result

        except Exception as e:

            return {
                "evidence_id": evidence.evidence_id,
                "name": evidence.name,
                "type": evidence_type,
                "status": "FAILED",
                "message": str(e)
            }

    def execute_all(self, evidence_list):

        results = []

        # Multiple evidence can execute simultaneously.
        with ThreadPoolExecutor(
            max_workers=min(8, max(1, len(evidence_list)))
        ) as executor:

            futures = {
                executor.submit(
                    self.execute_one,
                    evidence
                ): evidence
                for evidence in evidence_list
            }

            for future in as_completed(futures):

                evidence = futures[future]

                try:

                    result = future.result()

                except Exception as e:

                    result = {
                        "evidence_id": evidence.evidence_id,
                        "name": evidence.name,
                        "type": evidence.evidence_type,
                        "status": "FAILED",
                        "message": str(e)
                    }

                results.append(result)

        return results