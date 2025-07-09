from dataclasses import field
from datetime import datetime
from typing import Optional

import pymongo
from beanie import Document
from pydantic import Field


class Request(Document):
    client: str = Field(default=None)
    client_id: Optional[str] = Field(default=None)

    client_port: int
    request: str
    response: str = Field(default=None)
    protocol: str = Field(default="unknown")
    error: bool = False

    # Security fields
    is_suspicious: bool = False
    attack_type: str = ""
    severity: str = "low"

    response_time: datetime = Field(default=None)
    request_time: datetime = field(default_factory=datetime.now)

    class Settings:
        indexes = [
            "request_response",
            [
                ("request", pymongo.TEXT),
                ("response", pymongo.TEXT),
            ]
        ]
