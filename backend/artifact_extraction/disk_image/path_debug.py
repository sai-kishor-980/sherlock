import os
from pathlib import Path


def log_path_boundary(stage, value):
    try:
        resolved = str(Path(value).resolve(strict=False))
    except (OSError, TypeError, ValueError) as error:
        resolved = f"<resolve failed: {error}>"

    print(
        f"[PATH] stage={stage} original={value!r} "
        f"type={type(value).__name__} cwd={os.getcwd()!r} "
        f"resolved={resolved!r}",
        flush=True,
    )