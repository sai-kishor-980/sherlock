from ..base_extractor import BaseExtractor


class PrefetchExtractor(BaseExtractor):
    """
    Extract Windows Prefetch files.
    """

    PREFETCH_PATH = "/Windows/Prefetch"

    def extract(self):

        output_dir = self.create_output_directory(
            "prefetch"
        )

        if not self.filesystem.exists(
            self.PREFETCH_PATH
        ):

            return self.build_result(
                artifact="Prefetch",
                status="SKIPPED",
                files=0,
                message="Prefetch directory not found."
            )

        copied_files = self.filesystem.copy_directory(
            self.PREFETCH_PATH,
            str(output_dir)
        )

        status = (
            "SUCCESS"
            if copied_files
            else "SKIPPED"
        )

        return self.build_result(
            artifact="Prefetch",
            status=status,
            files=copied_files,
            message=(
                f"{copied_files} prefetch "
                f"file(s) extracted."
            )
        )