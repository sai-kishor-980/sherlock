from pathlib import Path

from ..base_extractor import BaseExtractor


class RegistryExtractor(BaseExtractor):
    """
    Extract Windows Registry hives.

    Extracts:
    - SYSTEM
    - SOFTWARE
    - SAM
    - SECURITY
    - DEFAULT
    - Amcache.hve
    - NTUSER.DAT for each discovered user
    - UsrClass.dat for each discovered user
    """

    SYSTEM_HIVES = [
        "SYSTEM",
        "SOFTWARE",
        "SAM",
        "SECURITY",
        "DEFAULT"
    ]

    def extract(self):
        output_dir = self.create_output_directory("registry")

        extracted = 0

        # -------------------------
        # System Registry Hives
        # -------------------------
        system_config = "/Windows/System32/config"

        for hive in self.SYSTEM_HIVES:

            image_path = f"{system_config}/{hive}"

            if not self.filesystem.exists(image_path):
                continue

            try:
                self.filesystem.copy_file(
                    image_path,
                    str(output_dir / hive)
                )

                extracted += 1

            except Exception as e:
                self.log(f"Failed to extract {hive}: {e}")

        # Extract Amcache
        amcache = "/Windows/AppCompat/Programs/Amcache.hve"
        if self.filesystem.exists(amcache):
            try:
                self.filesystem.copy_file(
                    amcache,
                    str(output_dir / "Amcache.hve")
                )
                extracted += 1
            except Exception as e:
                self.log(f"Failed to extract Amcache.hve: {e}")

        # -------------------------
        # User Registry Hives
        # -------------------------

        if self.filesystem.exists("/Users"):
            user_root = "/Users"
        elif self.filesystem.exists("/Documents and Settings"):
            user_root = "/Documents and Settings"
        else:
            user_root = None

        if user_root:

            for user in self.users:

                ntuser = f"{user_root}/{user}/NTUSER.DAT"

                if not self.filesystem.exists(ntuser):
                    continue

                try:

                    self.filesystem.copy_file(
                        ntuser,
                        str(output_dir / f"{user}_NTUSER.DAT")
                    )

                    extracted += 1

                except Exception as e:
                    self.log(
                        f"Failed to extract NTUSER.DAT for {user}: {e}"
                    )

                # Extract UsrClass.dat
                usrclass = f"{user_root}/{user}/AppData/Local/Microsoft/Windows/UsrClass.dat"
                if self.filesystem.exists(usrclass):
                    try:
                        self.filesystem.copy_file(
                            usrclass,
                            str(output_dir / f"{user}_UsrClass.dat")
                        )
                        extracted += 1
                    except Exception as e:
                        self.log(
                            f"Failed to extract UsrClass.dat for {user}: {e}"
                        )

        status = "SUCCESS" if extracted else "SKIPPED"

        return self.build_result(
            artifact="Registry",
            status=status,
            files=extracted,
            message=f"{extracted} registry hive(s) extracted."
        )