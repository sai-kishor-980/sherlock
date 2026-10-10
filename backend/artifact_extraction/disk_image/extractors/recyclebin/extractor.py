from ..base_extractor import BaseExtractor


class RecycleBinExtractor(BaseExtractor):
    """
    Extract Windows Recycle Bin contents.
    """

    RECYCLE_BIN_PATH = "/$Recycle.Bin"

    def extract(self):

        output_dir = self.create_output_directory(
            "recycle_bin"
        )

        if not self.filesystem.exists(
            self.RECYCLE_BIN_PATH
        ):

            return self.build_result(
                artifact="Recycle Bin",
                status="SKIPPED",
                files=0,
                message="Recycle Bin not found."
            )

        copied_files = self.filesystem.copy_directory(
            self.RECYCLE_BIN_PATH,
            str(output_dir)
        )

        status = (
            "SUCCESS"
            if copied_files
            else "SKIPPED"
        )

        return self.build_result(
            artifact="Recycle Bin",
            status=status,
            files=copied_files,
            message=(
                f"{copied_files} recycle bin "
                f"file(s) extracted."
            )
        )