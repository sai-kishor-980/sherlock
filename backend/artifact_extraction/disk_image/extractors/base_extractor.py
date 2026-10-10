from abc import ABC, abstractmethod
from pathlib import Path
import shutil


class BaseExtractor(ABC):
    """
    Base class for all artifact extractors.

    Every extractor receives the same extraction context and
    returns a standardized result.
    """

    def __init__(self, context):
        self.context = context

        self.filesystem = context.filesystem
        self.partition = context.partition
        self.users = context.users
        self.output_dir = Path(context.output_dir)
        self.logger = getattr(context, "logger", None)

    @abstractmethod
    def extract(self):
        """
        Execute artifact extraction.

        Must return:
        {
            "artifact": str,
            "status": str,
            "files": int,
            "message": str
        }
        """
        pass

    def create_output_directory(self, name):
        """
        Create an output directory for the artifact.
        """
        directory = self.output_dir / name
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def log(self, message):
        """
        Log a message if a logger exists.
        """
        if self.logger:
            self.logger.info(message)

    def build_result(
        self,
        artifact,
        status,
        files=0,
        message=""
    ):
        """
        Create a standardized extractor result.
        """
        return {
            "artifact": artifact,
            "status": status,
            "files": files,
            "message": message,
        }

    def copy_local_file(self, source, destination):
        """
        Copy a local file.
        Mainly used when an artifact has already been exported.
        """
        shutil.copy2(source, destination)