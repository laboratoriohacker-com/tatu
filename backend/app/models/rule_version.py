from sqlalchemy import Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class RuleVersion(Base):
    __tablename__ = "rule_version"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, default=1)
