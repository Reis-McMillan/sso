import uuid
from datetime import datetime, timezone
from typing import List, TYPE_CHECKING
from pydantic import EmailStr, field_validator
from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel, Session, select, Relationship

from verys.models.identity_role import IdentityRole

if TYPE_CHECKING:
    from verys.models.role import Role


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
    roles: List["Role"] = Relationship(
        back_populates="identities", link_model=IdentityRole
    )

    @field_validator('email', mode='before')
    @classmethod
    def transform_email(cls, v: str):
        if isinstance(v, str):
            return v.strip().lower()
        return v

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
    def get_by_id(cls, session: Session, id: int | List[int]):
        if isinstance(id, int):
            statement = select(cls).where(cls.id == id, cls.closed == False)
            return session.exec(statement).first()
        elif isinstance(id, list):
            statement = select(cls).where(cls.id.in_(id), cls.closed == False)
            return list(session.exec(statement).all())

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
    ):
        email = cls.transform_email(email)
        db_identity = cls.get(session, email)
        if not db_identity:
            return None
        validated = cls.model_validate({
            "first_name": db_identity.first_name,
            "last_name": db_identity.last_name,
            "email": new_email if new_email else db_identity.email,
            "auth_key": new_key if new_key else db_identity.auth_key,
            "expires": new_expires if new_expires else db_identity.expires,
        })
        db_identity.email = validated.email
        db_identity.auth_key = validated.auth_key
        db_identity.expires = validated.expires
        session.add(db_identity)
        session.commit()
        session.refresh(db_identity)
        return db_identity

    @classmethod
    def all(cls, session: Session):
        statement = select(cls)
        return session.exec(statement).all()
