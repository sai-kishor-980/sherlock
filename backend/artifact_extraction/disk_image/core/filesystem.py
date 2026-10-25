import os
import pytsk3


class FileSystem:
    """
    Wrapper around pytsk3.FS_Info.

    Provides helper methods for accessing files and
    directories inside a mounted filesystem.
    """

    def __init__(self, image_reader, partition):
        self.image_reader = image_reader
        self.partition = partition

        self._fs = pytsk3.FS_Info(
            self.image_reader.get_img_info(),
            offset=partition.start * 512
        )

    @property
    def fs(self):
        return self._fs

    def open(self, path):
        """
        Open a file or directory.
        """
        return self._fs.open(path)

    def open_meta(self, addr):
        """
        Open a file or directory by its metadata/inode address.
        """
        return self._fs.open_meta(addr)

    def exists(self, path):
        """
        Check whether a file or directory exists.
        """
        try:
            self._fs.open(path)
            return True
        except Exception:
            return False

    def open_directory(self, path="/"):
        """
        Open a directory.
        """
        return self._fs.open_dir(path=path)

    def list_directory(self, path="/"):
        """
        List directory contents.

        Returns:
            list of dictionaries:
            {
                "name": "...",
                "type": "File" | "Directory"
            }
        """

        directory = self.open_directory(path)

        entries = []

        for entry in directory:

            try:
                name = entry.info.name.name.decode(
                    "utf-8",
                    errors="replace"
                )

                if name in (".", ".."):
                    continue

                entry_type = "Unknown"

                if entry.info.meta:

                    if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        entry_type = "Directory"

                    elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        entry_type = "File"

                entries.append({
                    "name": name,
                    "type": entry_type
                })

            except Exception:
                continue

        return entries

    def copy_file(self, source_path, destination_path, chunk_size=4096):
        """
        Copy a single file from the image to the host.
        """

        file_obj = self._fs.open(source_path)

        size = file_obj.info.meta.size

        os.makedirs(
            os.path.dirname(destination_path),
            exist_ok=True
        )

        with open(destination_path, "wb") as outfile:

            offset = 0

            while offset < size:

                read_size = min(chunk_size, size - offset)

                data = file_obj.read_random(
                    offset,
                    read_size
                )

                if not data:
                    break

                outfile.write(data)

                offset += len(data)

        return destination_path

    def copy_directory(self, source_directory, destination_directory):
        """
        Recursively copy an entire directory from the image
        to the host filesystem.

        Args:
            source_directory (str): Directory inside image.
            destination_directory (str): Host output directory.

        Returns:
            int: Number of files copied.
        """

        copied_files = 0

        os.makedirs(destination_directory, exist_ok=True)

        try:
            directory = self._fs.open_dir(path=source_directory)

        except Exception:
            return copied_files

        for entry in directory:

            try:
                name = entry.info.name.name.decode(
                    "utf-8",
                    errors="ignore"
                )

                if name in (".", ".."):
                    continue

                image_path = f"{source_directory}/{name}"
                host_path = os.path.join(destination_directory, name)

                if (
                    entry.info.meta and
                    entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                ):

                    copied_files += self.copy_directory(
                        image_path,
                        host_path
                    )

                elif (
                    entry.info.meta and
                    entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG
                ):

                    try:
                        self.copy_file(
                            image_path,
                            host_path
                        )
                        copied_files += 1

                    except Exception:
                        continue

            except Exception:
                continue

        return copied_files