from sqlalchemy.orm import selectinload
from sqlmodel import select

from app.database import select_one
from app.projects.models import ProjectDB
from app.admin.models import UserDB




async def get_users_in_project_db(project_id: str) -> list[UserDB]:
    """Retrieve all users in a project."""
    statement = (
        select(ProjectDB)
        .where(ProjectDB.id == project_id)
        .options(selectinload(ProjectDB.users))
    )
    project = await select_one(statement)
    if not project:
        return []
    
    return project.users


async def add_user_to_project_db(project_id: str, user_id: str) -> UserDB:
    """Add a user to a project."""
    statement = (
        select(UserDB)
        .where(UserDB.id == user_id)
        .options(selectinload(UserDB.projects))
    )
    user = await select_one(statement)
    if not user:
        return None

    # Assuming you have a function to add the user to the project
    # This is just a placeholder implementation
    project = await select_one(
        select(ProjectDB).where(ProjectDB.id == project_id)
    )
    if not project:
        return None

    project.users.append(user)
    return user


async def remove_user_from_project_db(project_id: str, user_id: str) -> bool:
    """Remove a user from a project."""
    statement = (
        select(UserDB)
        .where(UserDB.id == user_id)
        .options(selectinload(UserDB.projects))
    )
    user = await select_one(statement)
    if not user:
        return False

    # Assuming you have a function to remove the user from the project
    # This is just a placeholder implementation
    project = await select_one(
        select(ProjectDB).where(ProjectDB.id == project_id)
    )
    if not project:
        return False

    project.users.remove(user)
    return True