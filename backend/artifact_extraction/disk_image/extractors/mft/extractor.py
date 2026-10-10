from ..base_extractor import BaseExtractor


class MFTExtractor(BaseExtractor):
    """
    Extract the NTFS Master File Table ($MFT).
    """

    MFT_PATH = "/$MFT"

    def extract(self):

        output_dir = self.create_output_directory("mft")

        destination = output_dir / "$MFT"

        if not self.filesystem.exists(self.MFT_PATH):

            return self.build_result(
                artifact="MFT",
                status="SKIPPED",
                files=0,
                message="$MFT not found."
            )

        try:

            self.filesystem.copy_file(
                self.MFT_PATH,
                str(destination)
            )

            return self.build_result(
                artifact="MFT",
                status="SUCCESS",
                files=1,
                message="$MFT extracted successfully."
            )

        except Exception as e:

            return self.build_result(
                artifact="MFT",
                status="FAILED",
                files=0,
                message=str(e)
            )