from sqlmodel import SQLModel

from app import create_app
from app.logger import logger


metadata = SQLModel.metadata


fastapi_app = create_app()
logger.info("Application started")


@fastapi_app.get("/health")
async def test():
    return {"status": "success"}