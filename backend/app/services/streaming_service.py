"""
Large File Streaming Service for HMACFR.

Provides asynchronous and chunked streaming download handlers for large forensic evidence files.
"""

from pathlib import Path
from typing import AsyncGenerator, Union
from fastapi.responses import StreamingResponse
from app.utils.stream_utils import read_file_chunks_async
from app.core.logger import log_error_event


class StreamService:
    """
    Service managing chunked HTTP streaming downloads for large forensic artifacts.
    """

    DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MB chunk

    @classmethod
    def create_streaming_response(
        cls, filepath: Union[str, Path], media_type: str = "application/octet-stream", filename: str = None
    ) -> StreamingResponse:
        """
        Creates a FastAPI StreamingResponse for streaming a large file to clients in chunks.

        :param filepath: Path to file on disk.
        :param media_type: HTTP content type header.
        :param filename: Optional download filename header.
        :return: StreamingResponse instance.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        if not path.is_file():
            err_msg = f"Cannot stream file: '{path}' does not exist."
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        out_name = filename or path.name
        headers = {
            "Content-Disposition": f'attachment; filename="{out_name}"',
            "Content-Length": str(path.stat().st_size),
        }

        async def chunk_generator() -> AsyncGenerator[bytes, None]:
            async for chunk in read_file_chunks_async(path, cls.DEFAULT_CHUNK_SIZE):
                yield chunk

        return StreamingResponse(chunk_generator(), media_type=media_type, headers=headers)
