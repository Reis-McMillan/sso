import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, ARRAY, String, DateTime
from sqlmodel import Field, SQLModel, Session, select


class OAuthClient(SQLModel, table=True):
    __tablename__ = "oauth_client"

    id: int | None = Field(default=None, primary_key=True)
    client_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        unique=True,
        index=True,
    )
    client_secret_hash: Optional[str] = Field(default=None)
    client_name: str = Field()
    redirect_uris: List[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String)),
    )
    allowed_scopes: List[str] = Field(
        default_factory=lambda: ["openid"],
        sa_column=Column(ARRAY(String)),
    )
    prm_uri: Optional[str] = Field(default=None)
    required_scopes: Optional[List[str]] = Field(
        default_factory=lambda: [],
        sa_column=Column(ARRAY(String))
    )
    grant_types: List[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"],
        sa_column=Column(ARRAY(String)),
    )
    response_types: List[str] = Field(
        default_factory=lambda: ["code"],
        sa_column=Column(ARRAY(String)),
    )
    token_endpoint_auth_method: str = Field(default="client_secret_basic")
    is_public: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    owner_email: Optional[str] = Field(default=None)

    @classmethod
    def get_by_client_id(cls, session: Session, client_id: str):
        statement = select(cls).where(cls.client_id == client_id)
        return session.exec(statement).first()

    @classmethod
    def all(cls, session: Session):
        return session.exec(select(cls)).all()
