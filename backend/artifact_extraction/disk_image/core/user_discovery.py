class UserDiscovery:
    """
    Discovers user profiles from a Windows filesystem.

    Responsibilities:
    - Enumerate user profile directories under C:\\Users.
    - Exclude system/default profiles.
    - Return a list of valid usernames.
    """

    SYSTEM_PROFILES = {
        "Public",
        "Default",
        "Default User",
        "All Users",
        "desktop.ini",
    }

    def __init__(self, filesystem):
        """
        Args:
            filesystem (FileSystem): Mounted filesystem wrapper.
        """
        self.filesystem = filesystem

    def get_users(self):
        """
        Returns:
            list[str]: List of discovered user profile names.
        """
        users = []

        users_path = "/Users"

        if not self.filesystem.exists(users_path):
            return users

        try:
            directory = self.filesystem.open_directory(users_path)

            for entry in directory:

                try:
                    name = entry.info.name.name.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    if name in (".", ".."):
                        continue

                    if name in self.SYSTEM_PROFILES:
                        continue

                    meta = entry.info.meta

                    if meta is None:
                        continue

                    if meta.type != 2:      # Directory
                        continue

                    users.append(name)

                except Exception:
                    continue

        except Exception:
            pass

        return sorted(users)