from sqlalchemy import String, Text, Boolean, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    format: Mapped[str] = mapped_column(String(10))  # yaml | yara
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(10))  # builtin | custom
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    mode: Mapped[str] = mapped_column(String(10), default="audit")  # audit | strict
    action: Mapped[str] = mapped_column(String(10))  # block | warn | log
    hook_event: Mapped[str] = mapped_column(String(50))
    matcher: Mapped[str] = mapped_column(String(255))
    version_added: Mapped[int] = mapped_column(Integer, default=1)
    compliance_mappings: Mapped[list] = mapped_column(JSON, default=list)
