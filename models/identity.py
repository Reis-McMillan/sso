import uuid
from datetime import datetime, timezone
from typing import List
from enum import Enum
from pydantic import EmailStr, field_serializer, field_validator
from sqlalchemy import Column, ARRAY, String, DateTime
from sqlmodel import Field, SQLModel, Session, select

from config import config

class Role(str, Enum):
    ADMIN = 'admin'
    SERVICE_ACCOUNT = 'service-account'
    COIN_MANAGER = 'coin-manager'
    DEFAULT = 'default'

class Identity(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    first_name: str = Field()
    last_name: str = Field()
    email: EmailStr = Field(unique=True)
    email_verified: bool = Field(default=False)
    auth_key: str = Field()
    expires: datetime = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    origination: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True))
    )
    closed: bool = Field(default=False)
    last_auth_time: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True)),
    )
    roles: List[Role] = Field(
        default_factory=lambda: [Role.DEFAULT],
        sa_column=Column(ARRAY(String))
    )

    @field_validator('email', mode='before')
    @classmethod
    def transform_email(cls, v: str):
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_serializer('roles')
    def serialize_roles(self, roles: List[Role]) -> List[str]:
        return [r.value if isinstance(r, Role) else r for r in roles]

    @staticmethod
    def make_auth_key() -> str:
        return str(uuid.uuid4())

    @classmethod
    def new(
        cls,
        session: Session,
        first_name: str,
        last_name: str,
        email: str,
        key: str,
        expires: datetime
    ):
        email = cls.transform_email(email)
        db_identity = cls.model_validate({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "auth_key": key,
            "expires": expires
        })
        session.add(db_identity)
        session.commit()
        session.refresh(db_identity)
        return db_identity

    @classmethod
    def get(cls, session: Session, email: str):
        email = cls.transform_email(email)
        statement = select(cls).where(cls.email == email, cls.closed == False)
        return session.exec(statement).first()

    @classmethod
    def get_by_id(cls, session: Session, id: int):
        statement = select(cls).where(cls.id == id, cls.closed == False)
        return session.exec(statement).first()

    @classmethod
    def close(cls, session: Session, email: str):
        email = cls.transform_email(email)
        db_identity = cls.get(session, email)
        if db_identity:
            db_identity.closed = True
            session.add(db_identity)
            session.commit()
            session.refresh(db_identity)
        return db_identity

    @classmethod
    def update(
        cls,
        session: Session,
        email: str,
        new_email: str = None,
        new_key: str = None,
        new_expires: datetime = None,
        new_roles: list[Role] = None
    ):
        email = cls.transform_email(email)
        db_identity = cls.get(session, email)
        if not db_identity:
            return None
        if new_roles is not None and len(new_roles) == 0:
            new_roles = [Role.DEFAULT]
        if db_identity:
            validated = cls.model_validate({
                "first_name": db_identity.first_name,
                "last_name": db_identity.last_name,
                "email": new_email if new_email else db_identity.email,
                "auth_key": new_key if new_key else db_identity.auth_key,
                "expires": new_expires if new_expires else db_identity.expires,
                "roles": new_roles if new_roles is not None else db_identity.roles,
            })
            db_identity.email = validated.email
            db_identity.auth_key = validated.auth_key
            db_identity.expires = validated.expires
            db_identity.roles = validated.roles
            session.add(db_identity)
            session.commit()
            session.refresh(db_identity)
        return db_identity

    @classmethod
    def update_roles(cls, session: Session, email: str, roles: list[Role]):
        return cls.update(session, email, new_roles=roles)

    @classmethod
    def all(cls, session: Session):
        statement = select(cls)
        return session.exec(statement).all()