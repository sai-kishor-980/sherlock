import pytsk3


class PartitionExtractor:
    """
    Enumerates mountable filesystem partitions from a disk image.

    Responsibilities:
    - Read the partition table.
    - Skip unallocated/metadata entries.
    - Return only partitions that contain a valid filesystem.
    """

    def __init__(self, image_reader):
        """
        Args:
            image_reader: Instance of RawImageReader or E01ImageReader.
        """
        self.image_reader = image_reader

    def get_partitions(self):
        """
        Returns:
            list[pytsk3.TSK_VS_PART_INFO]: Mountable filesystem partitions.
        """
        volume = self.image_reader.get_volume_info()
        partitions = []

        img_info = self.image_reader.get_img_info()

        for partition in volume:

            try:
                # Skip empty partitions
                if partition.len == 0:
                    continue

                description = partition.desc.decode(
                    "utf-8",
                    errors="ignore"
                ).strip().lower()

                # Skip obvious non-data partitions
                if (
                    "unallocated" in description or
                    "metadata" in description
                ):
                    continue

                # Verify that this partition actually contains a filesystem
                try:
                    pytsk3.FS_Info(
                        img_info,
                        offset=partition.start * 512
                    )

                    partitions.append(partition)

                except Exception:
                    # Not a valid filesystem (EFI/MSR/GPT/etc.)
                    continue

            except Exception:
                continue

        if not partitions:
            raise RuntimeError("No mountable filesystem partitions found.")

        return partitions