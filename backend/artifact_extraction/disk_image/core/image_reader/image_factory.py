import os
import ntpath

from .raw_reader import RawImageReader
from .e01_reader import E01ImageReader
from path_debug import log_path_boundary


class ImageFactory:
    """
    Factory class responsible for returning the correct
    image reader based on the disk image format.
    """

    _READERS = (
        RawImageReader,
        E01ImageReader,
    )

    @classmethod
    def create(cls, image_path: str):
        """
        Create and return the appropriate image reader.

        Args:
            image_path (str): Path to the disk image.

        Returns:
            BaseImageReader

        Raises:
            ValueError: If the image format is unsupported.
        """

        log_path_boundary("ImageFactory input", image_path)

        image_path = os.fspath(image_path)
        if os.name == "nt" and ntpath.isabs(image_path):
            image_path = ntpath.normpath(image_path)
        else:
            image_path = os.path.abspath(os.path.normpath(image_path))

        log_path_boundary("ImageFactory normalized", image_path)

        if not os.path.exists(image_path):
            raise FileNotFoundError(
                f"Disk image not found: {image_path}"
            )

        for reader in cls._READERS:
            if reader.supports(image_path):
                return reader(image_path)

        raise ValueError(
            f"Unsupported disk image format: {image_path}"
        )