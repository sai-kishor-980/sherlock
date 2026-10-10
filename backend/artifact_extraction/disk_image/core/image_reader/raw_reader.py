import os
import pytsk3

from .base_reader import BaseImageReader


class RawImageReader(BaseImageReader):
    """
    Reader for RAW disk images (.img, .dd, .001, .bin, etc.).
    Wraps pytsk3.Img_Info and provides a common interface
    used by the rest of the extraction framework.
    """

    SUPPORTED_EXTENSIONS = {
        ".img",
        ".dd",
        ".001",
        ".bin",
        ".raw",
    }

    def __init__(self, image_path: str):
        self.image_path = image_path
        self._img_info = None

    def open(self):
        """
        Open the RAW disk image.
        """
        if not os.path.exists(self.image_path):
            raise FileNotFoundError(
                f"Disk image not found: {self.image_path}"
            )

        self._img_info = pytsk3.Img_Info(self.image_path)
        return self._img_info

    def close(self):
        """
        Release the image object.
        """
        self._img_info = None

    def get_img_info(self):
        """
        Return the underlying pytsk3.Img_Info object.
        """
        if self._img_info is None:
            raise RuntimeError("Image has not been opened.")

        return self._img_info

    def get_volume_info(self):
        """
        Return the partition table (Volume_Info).

        Raises:
            RuntimeError if no partition table exists.
        """
        if self._img_info is None:
            raise RuntimeError("Image has not been opened.")

        try:
            return pytsk3.Volume_Info(self._img_info)
        except IOError as e:
            raise RuntimeError(
                f"Unable to read partition table: {e}"
            )

    @classmethod
    def supports(cls, image_path: str) -> bool:
        """
        Check whether this reader supports the supplied image.
        """
        _, ext = os.path.splitext(image_path)
        return ext.lower() in cls.SUPPORTED_EXTENSIONS