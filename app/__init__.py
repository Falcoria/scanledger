from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends

from app.config import config, Environment
from app.logger import logger
from app.database import init_db
from app.admin.router import admin_router
from app.initializers import init_primary_users
from app.admin.dependencies import validate_admin_access
from app.projects.router import projects_router
from app.error_handlers import register_error_handlers


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        #await delete_all_tables()
        await init_db()
        await init_primary_users()
        #await create_directories()
        yield
    finally:
        logger.info("Application shutdown")


def create_app():
    app = FastAPI(
        docs_url=config.docs_url, 
        redoc_url=config.redoc_url,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "admin", "description": "Admin operations"},
            {"name": "projects", "description": "Project CRUD"},
            {"name": "projects:ips", "description": "Manage IPs within a project"},
            {"name": "projects:users", "description": "Manage project-user relationships"},
        ],
        swagger_ui_parameters={"defaultModelsExpandDepth": -1}
    )

    register_error_handlers(app)

    app.include_router(
        admin_router, 
        prefix="/admin", 
        dependencies=[Depends(validate_admin_access)],
        tags=["admin"],
        include_in_schema=config.environment == Environment.development
    )

    app.include_router(
        projects_router, 
        prefix="/projects"
    )

    return app