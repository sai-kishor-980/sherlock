class ExtractionContext:
    """
    Shared context object passed to every extractor.
    """

    def __init__(
        self,
        filesystem,
        partition,
        users,
        output_dir,
        partition_id,
        logger=None,
        image_name=None,
    ):
        self.filesystem = filesystem
        self.partition = partition
        self.users = users
        self.output_dir = output_dir
        self.logger = logger
        self.image_name = image_name
        self.partition_id = partition_id