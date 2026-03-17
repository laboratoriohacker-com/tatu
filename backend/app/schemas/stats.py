from typing import Any
from pydantic import BaseModel


class OverviewStats(BaseModel):
    total_events: int
    total_blocks: int
    active_sessions: int
    secrets_caught: int
    block_rate: float


class TimelineBucket(BaseModel):
    hour: str
    events: int
    blocks: int


class DeveloperStats(BaseModel):
    name: str
    sessions: int
    blocks: int
    risk: str


class ComplianceFramework(BaseModel):
    framework: str
    controls: int
    covered: int
    evidenced: int
    status: str
    percentage: int


class ComplianceMapping(BaseModel):
    hook: str
    maps: str


class ComplianceResponse(BaseModel):
    frameworks: list[ComplianceFramework]
    mappings: list[ComplianceMapping]


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    per_page: int
    pages: int
