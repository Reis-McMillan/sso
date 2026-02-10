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
    DEFAULT = 'default'

class Identity(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    auth_key: str = Field()
    expires: datetime = Field(
        sa_column=Column(DateTime(timezone=True))
    )
    origination: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True))
    )
    closed: bool = Field(default=False)
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
    def new(cls, session: Session, email: str, key: str, expires: datetime):
        email = cls.transform_email(email)
        db_identity = cls.model_validate({
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
    def update(cls, session: Session, email: str, new_key: str, expires: datetime):
        email = cls.transform_email(email)
        db_identity = cls.get(session, email)
        if db_identity:
            validated = cls.model_validate({
                "email": db_identity.email,
                "auth_key": new_key,
                "expires": expires
            })
            db_identity.auth_key = validated.auth_key
            db_identity.expires = validated.expires
            session.add(db_identity)
            session.commit()
            session.refresh(db_identity)
        return db_identity

    @classmethod
    def update_roles(cls, session: Session, email: str, new_roles: List[Role]):
        email = cls.transform_email(email)
        db_identity = cls.get(session, email)
        if db_identity:
            db_identity.roles = new_roles
            session.add(db_identity)
            session.commit()
            session.refresh(db_identity)
        return db_identity

    @classmethod
    def all(cls, session: Session):
        statement = select(cls)
        return session.exec(statement).all()