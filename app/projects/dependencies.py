import os

import aiofiles
from fastapi import HTTPException, status, UploadFile, File

from app.config import config
from app.constants.messages import Message
from app.config import config


async def file_upload(
    file: UploadFile = File(...)
) -> str:
    """
    Dependency for file upload.
    Saves uploaded file to tmp, checks size, returns path.
    """
    max_size = config.max_file_upload_size
    real_file_size = 0

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as temp:
        temp_name = temp.name
        while chunk := await file.read(config.default_chunk_size):
            real_file_size += len(chunk)
            if real_file_size > max_size:
                await temp.close()
                os.remove(temp_name)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=Message.FILE_TOO_LARGE,
                )
            await temp.write(chunk)

    return temp_name
