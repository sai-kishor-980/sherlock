import os

try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    pyewf = None
    HAS_PYEWF = False

import pytsk3

from .base_reader import BaseImageReader
from path_debug import log_path_boundary


class EWFImgInfo(pytsk3.Img_Info):
    """
    Adapter that allows pytsk3 to read E01 images through pyewf.
    """

    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


class E01ImageReader(BaseImageReader):
    """
    Reader for EnCase Evidence Files (.E01).
    """

    SUPPORTED_EXTENSIONS = {
        ".e01",
        ".ex01",
    }

    def __init__(self, image_path: str):
        log_path_boundary("E01ImageReader.__init__", image_path)
        self.image_path = image_path
        self._ewf_handle = None
        self._img_info = None

    def open(self):
        """
        Open the E01 image.
        """
        log_path_boundary("E01ImageReader.open", self.image_path)

        if not HAS_PYEWF:
            raise RuntimeError(
                "pyewf library is not installed on this system. "
                "E01/Ex01 disk images require pyewf. Please use raw disk images (.raw, .dd, .img) "
                "or install pre-compiled pyewf wheels."
            )

        if not os.path.exists(self.image_path):
            raise FileNotFoundError(
                f"Disk image not found: {self.image_path}"
            )

        log_path_boundary("before pyewf.glob", self.image_path)
        filenames = pyewf.glob(self.image_path)

        self._ewf_handle = pyewf.handle()
        self._ewf_handle.open(filenames)

        self._img_info = EWFImgInfo(self._ewf_handle)

        return self._img_info

    def close(self):
        """
        Close the E01 image.
        """
        if self._img_info:
            self._img_info.close()

        self._img_info = None
        self._ewf_handle = None

    def get_img_info(self):
        """
        Return the pytsk3 image object.
        """
        if self._img_info is None:
            raise RuntimeError("Image has not been opened.")

        return self._img_info

    def get_volume_info(self):
        """
        Return the partition table.
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
    def supports(cls, image_path: str):
        _, ext = os.path.splitext(image_path)
        return ext.lower() in cls.SUPPORTED_EXTENSIONS