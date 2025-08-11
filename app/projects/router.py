import os
from uuid import UUID
from typing import List, Annotated, TYPE_CHECKING, Dict, Tuple

from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Body,
    Depends,
    Query,
)

from app.admin.dependencies import validate_project_access, validate_user_access
from app.admin.models import UserDB
from app.constants.messages import Message
from app.projects.ips.router import ips_router
from app.projects.users.router import project_user_router
from app.projects.history.router import history_router

from .service import (
    get_projectdb,
    get_projectsdb,
    create_projectdb,
    modify_projectdb,
    delete_projectdb
)
from .schemas import (
    ProjectIn,
    ProjectBase,
    ProjectOut,
)
from .models import ProjectDB


projects_router = APIRouter()
projects_router.include_router(
    history_router, 
    prefix="/{project_id}/history", 
    tags=["projects:history"], 
    dependencies=[Depends(validate_project_access)]
)
projects_router.include_router(
    ips_router, 
    prefix="/{project_id}/ips", 
    tags=["projects:ips"], 
    dependencies=[Depends(validate_project_access)]
)
projects_router.include_router(
    project_user_router,
    prefix="/{project_id}/users",
    tags=["projects:users"],
    dependencies=[Depends(validate_project_access)]
)


@projects_router.get(
    "", 
    summary="Get all projects", 
    tags=["projects"],
    response_model=List[ProjectOut]
)
async def get_projects(
    current_user: Annotated[UserDB, Depends(validate_user_access)],
):
    """ Retrieve all projects and its data. """
    projects = await get_projectsdb(current_user)
    if not projects:
        return []
    return projects


@projects_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create project",
    tags=["projects"],
    response_model=ProjectOut,
)
async def create_project(
    project_data: Annotated[ProjectIn, Body(...)],
    current_user: UserDB = Depends(validate_user_access)
):
    """ Create a new project with provided data """
    new_project = await create_projectdb(current_user, project_data)
    if new_project is None:
        raise HTTPException(status_code=400, detail=Message.PROJECT_ALREADY_EXISTS)

    return new_project


@projects_router.get(
    "/{project_id}",
    summary="Get project by ID",
    response_model=ProjectOut,
    tags=["projects"],
    dependencies=[Depends(validate_project_access)],
)
async def get_project(
    project_id: UUID,
):
    """ Retrieve a project by its ID """
    project = await get_projectdb(project_id)
    return project


@projects_router.put(
    "/{project_id}",
    summary="Update project",
    # response_model=Project,
    tags=["projects"],
    response_model=ProjectOut,
    dependencies=[Depends(validate_project_access)],
)
async def update_project(
    project_id: UUID, 
    project_data: Annotated[ProjectBase, Body()]
):
    '''
    Update data of an existing project (except name)
    '''
    updated_project = await modify_projectdb(project_id, project_data)
    if not updated_project:
        raise HTTPException(status_code=400, detail=Message.PROJECT_UPDATE_FAILED)
    return updated_project


@projects_router.delete(
    "/{project_id}",
    summary="Delete project",
    tags=["projects"],
    response_model=None,
    status_code=status.HTTP_204_NO_CONTENT
)
async def delete_project(
    project_and_user: Annotated[Tuple[ProjectDB, UserDB], Depends(validate_project_access)],
):
    """ Delete a project by its ID """
    current_project, current_user = project_and_user
    await delete_projectdb(current_project.id)
    if not current_project:
        raise HTTPException(status_code=400, detail=Message.PROJECT_DELETION_FAILED)
    return {"message": Message.PROJECT_DELETED}