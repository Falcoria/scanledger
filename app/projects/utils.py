import os
import uuid
import shutil
from datetime import datetime

import aiofiles
import aiofiles.os

from app.config import config
from app.logger import logger


async def create_directory(directory: str):
    """ Creates a directory if it does not exist."""
    if not await aiofiles.os.path.exists(directory):
        try:
            await aiofiles.os.makedirs(directory)
        except Exception as e:
            logger.error(f"Exception: create_directory {e}")
            return False
    return True


def generate_unique_filename(directory, file_extension="txt"):
    """ Generates a unique filename with a timestamp and a random string."""
    unique_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{timestamp}_{unique_id}.{file_extension}"
    filepath = os.path.join(directory, filename)
    return filepath


async def move_attachment(filepath: str):
    """ Moves the attachment to the attachment directory."""
    if not (os.path.exists(filepath) and os.path.isfile(filepath)):
        return None
    
    attachment_path = generate_unique_filename(config.attachment_dir)
    try:
        shutil.move(filepath, attachment_path)
        return attachment_path
    except Exception as e:
        logger.error(f"Exception: move_attachment {e}")
        return None


async def delete_file(filepath: str):
    """ Deletes the file at the given path."""
    try:
        await aiofiles.os.remove(filepath)
        return True
    except Exception as e:
        logger.error(f"Exception: delete_file {e}")
        return False


def merge_dicts_in_list(lst, key):
    """ Merges the dictionaries in the list based on the key."""
    merged_dict = {}
    for d in lst:
        if key in d:
            current_key_value = d[key]
            if current_key_value in merged_dict:
                merged_dict[current_key_value].update(d)
            else:
                merged_dict[current_key_value] = dict(d)
    return list(merged_dict.values())


async def read_and_decode_file(filepath: str) -> str:
    """ Reads, decodes and deletes the file at the given"""
    content = None
    try:
        async with aiofiles.open(filepath, 'r') as f:
            content = await f.read()
    except Exception as e:
        logger.error(f"Exception. {e}")
    finally:
        await delete_file(filepath)
        return content


def move_file(filepath: str, destination: str):
    """ Moves the file to the destination."""
    try:
        shutil.move(filepath, destination)
        return True
    except Exception as e:
        logger.error(f"Exception: move_file {e}")
        return False