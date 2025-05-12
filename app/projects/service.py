import os
import uuid
import shutil
from typing import List

import tempfile

from sqlmodel import select, delete
from sqlalchemy.orm import selectinload
#from sqlmodel.ext.asyncio.session import AsyncSession

from app.database import get_session, select_many, insert_and_refresh, select_one, delete_and_commit
from app.admin.models import UserDB
from app.config import config
from app.logger import logger
#from app.auth_management.models import UserDB
from .models import ProjectDB
from .schemas import ProjectBase, ProjectIn
from .utils import create_directory, generate_unique_filename, move_file
from .nmap_merger import main_nmap_merger


async def get_projectsdb(user: UserDB) -> List[ProjectDB]:
    """Retrieves all projects from the database for the current user."""
    statement = (
        select(ProjectDB)
        .join(ProjectDB.users)  # Ensures only projects associated with the user are retrieved
        .where(ProjectDB.users.any(UserDB.id == user.id))  # Checks association with current user
        .options(selectinload(ProjectDB.users))
    )
    projects = await select_many(statement)
    return projects


async def get_projectdb(project_id: uuid.UUID) -> ProjectDB:
    """Retrieves a specific project from the database."""
    statement = (
        select(ProjectDB)
        .where(ProjectDB.id == project_id)
        .options(selectinload(ProjectDB.users))
    )
    project = await select_one(statement)
    return project


async def create_projectdb(user: UserDB, project: ProjectIn):
    """ Creates a new project in the database."""
    new_projectdb = ProjectDB(**project.model_dump(exclude_unset=True))
    new_projectdb.users.append(user)
    create_projectdb = await insert_and_refresh(new_projectdb)
    if create_projectdb is None:
        return None
    
    # create directory for project
    return create_projectdb


async def modify_projectdb(
    project_id: uuid.UUID,
    project_data: ProjectBase
):
    """Modifies the project in the database."""
    statement = (
        select(ProjectDB)
        .where(ProjectDB.id == project_id)
        .options(selectinload(ProjectDB.users))
    )
    projectdb = await select_one(statement)
    if not projectdb:
        return None

    for key, value in project_data.model_dump(exclude_unset=True).items():
        setattr(projectdb, key, value)
    
    updated_projectdb = await insert_and_refresh(projectdb)
    return updated_projectdb


def get_project_directory(project_id: uuid.UUID):
    """ Retrieves the project directory."""
    return os.path.join(config.projects_dir, str(project_id))


async def delete_project_files(project_id: uuid.UUID):
    """ Deletes the project directory and all its files."""
    project_directory = get_project_directory(project_id)
    if not os.path.exists(project_directory):
        return True

    try:
        shutil.rmtree(project_directory)
        return True
    except Exception as e:
        logger.error(f"Exception:{e}")
        return False


async def delete_projectdb(project_id: uuid.UUID):
    """ Deletes the project from the database."""
    statement = delete(ProjectDB).where(ProjectDB.id == project_id)
    result = await delete_and_commit(statement)
    if not result:
        return False
    # Delete the project directory and its files
    deleted = await delete_project_files(project_id)
    return True


async def upload_project_file(project_id: uuid.UUID, uploaded_file: str):
    """ Uploads files to the project directory. Currently only nmap reports"""
    project_directory = get_project_directory(project_id)
    result = await create_directory(project_directory)
    if not result:
        return False

    new_file = generate_unique_filename(project_directory, "xml")
    result = move_file(uploaded_file, new_file)
    return result