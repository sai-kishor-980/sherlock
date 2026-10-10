from abc import ABC, abstractmethod


class BaseImageReader(ABC):
    """
    Abstract base class for all disk image readers.

    Every image reader (RAW, E01, AFF4, etc.) should implement
    this interface so the rest of the project doesn't need to know
    which image format is being used.
    """

    @abstractmethod
    def open(self):
        """Open the disk image."""
        pass

    @abstractmethod
    def close(self):
        """Close the disk image."""
        pass

    @abstractmethod
    def get_volume_info(self):
        """
        Return pytsk3.Volume_Info (or equivalent) for partition discovery.
        """
        pass