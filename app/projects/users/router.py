from fastapi import APIRouter
from fastapi import HTTPException

from .service import get_users_in_project_db, add_user_to_project_db, remove_user_from_project_db
from app.admin.schemas import UserOut
from app.constants.messages import Message


project_user_router = APIRouter()


@project_user_router.get(
    "",
    summary="Get all users in project",
    response_model=list[UserOut],
)
async def get_users_in_project(
    project_id: str
):
    """ Retrieve all users in a project. """
    # Assuming you have a function to get users in a project
    users = await get_users_in_project_db(project_id)
    if not users:
        return []
    return users


@project_user_router.post(
    "",
    summary="Add user to project",
    response_model=UserOut,
)
async def add_user_to_project(
    project_id: str,
    user_id: str
):
    """ Add a user to a project. """
    user = await add_user_to_project_db(project_id, user_id)
    if not user:
        return HTTPException(status_code=404, detail=Message.USER_OR_PROJECT_NOT_FOUND)
    return user


@project_user_router.delete(
    "",
    summary="Remove user from project",
    status_code=204,
)
async def remove_user_from_project(
    project_id: str,
    user_id: str
):
    """ Remove a user from a project. """
    success = await remove_user_from_project_db(project_id, user_id)
    if not success:
        return HTTPException(status_code=404, detail=Message.USER_OR_PROJECT_NOT_FOUND)