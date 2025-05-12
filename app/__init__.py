import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request

from app.config import config, Environment
from app.logger import logger
from app.database import init_db
from app.admin.router import admin_router
from app.initializers import init_admin_user
from app.admin.dependencies import validate_admin_access, validate_project_access
from app.projects.router import projects_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        #await delete_all_tables()
        await init_db()
        await init_admin_user()
        #await create_directories()
        yield
    finally:
        logger.info("Application shutdown")


def create_app():
    app = FastAPI(
        docs_url=config.docs_url, 
        redoc_url=config.redoc_url,
        lifespan=lifespan
    )

    app.include_router(
        admin_router, 
        prefix="/admin", 
        dependencies=[Depends(validate_admin_access)],
        tags=["admin"],
        include_in_schema=config.environment == Environment.development
    )

    app.include_router(
        projects_router, 
        prefix="/projects",
        tags=["projects"],
    )

    return app