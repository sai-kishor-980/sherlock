import os

def sanitize_filename(filename: str) -> str:
    """Sanitizes user-provided filename."""
    return os.path.basename(filename).replace(" ", "_")

def get_file_extension(filename: str) -> str:
    """Returns file extension in lowercase."""
    _, ext = os.path.splitext(filename)
    return ext.lower()
