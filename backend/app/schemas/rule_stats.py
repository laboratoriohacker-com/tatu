from pydantic import BaseModel


class RuleWithStats(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    category: str
    hook_event: str
    matcher: str
    enabled: bool
    compliance_mappings: list[str] = []
    triggers: int = 0
    blocks: int = 0
    block_rate: str = "0"
