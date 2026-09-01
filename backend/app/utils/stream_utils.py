"""
Stream Processing Utilities for HMACFR.

Provides high-efficiency chunked generators for streaming evidence files to APIs or hashers.
"""

from pathlib import Path
from typing import Generator, AsyncGenerator, Union
import asyncio


def read_file_chunks(
    filepath: Union[str, Path], chunk_size: int = 1024 * 1024
) -> Generator[bytes, None, None]:
    """
    Synchronous generator yielding file contents in fixed-size binary chunks.

    :param filepath: Path to file on disk.
    :param chunk_size: Chunk size in bytes (default 1 MB).
    """
    path = Path(filepath) if isinstance(filepath, str) else filepath
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


async def read_file_chunks_async(
    filepath: Union[str, Path], chunk_size: int = 1024 * 1024
) -> AsyncGenerator[bytes, None]:
    """
    Asynchronous generator yielding file contents in fixed-size binary chunks.

    :param filepath: Path to file on disk.
    :param chunk_size: Chunk size in bytes (default 1 MB).
    """
    path = Path(filepath) if isinstance(filepath, str) else filepath
    loop = asyncio.get_event_loop()
    
    with path.open("rb") as f:
        while True:
            chunk = await loop.run_in_executor(None, f.read, chunk_size)
            if not chunk:
                break
            yield chunk
