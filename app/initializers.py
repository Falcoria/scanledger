from sqlmodel import select, insert

from app.config import config
from app.admin.models import UserDB
from app.database import select_one, insert_one
from app.admin.utils import hash_password_without_salt
from app.logger import logger
#from app.projects.utils import create_directory


async def check_and_create_user(username: str, password: str, isadmin=False):
    statement = select(UserDB).where(UserDB.username == username)
    user = await select_one(statement)

    if user:
        logger.info(f"User '{username}' already exists")
        return False

    hashed_password = hash_password_without_salt(password)
    user = UserDB(username=username, hashed_token=hashed_password, isadmin=isadmin)
    result = await insert_one(user)
    if result:
        logger.info(f"User '{username}' created")
    else:
        logger.error(f"User '{username}' creation failed")
    
    return result


async def init_admin_user():
    return await check_and_create_user("admin", config.admin_token, isadmin=True)


async def init_tasker_user():
    return await check_and_create_user("tasker", config.tasker_token, isadmin=True)


async def init_primary_users():
    admin_result = await init_admin_user()
    tasker_result = await init_tasker_user()


#async def create_directories():
#    await create_directory(config.projects_dir)
#    await create_directory(config.attachment_dir)