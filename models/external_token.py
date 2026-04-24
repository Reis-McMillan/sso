from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, ARRAY, String, DateTime, UniqueConstraint
from sqlmodel import Field, SQLModel, Session, select
from pydantic import EmailStr

from utils.encryption import encrypt_field, decrypt_field


class ExternalToken(SQLModel, table=True):
    __tablename__ = "external_token"
    __table_args__ = (
        UniqueConstraint("identity_id", "subject", "provider_id", name="uq_external_token_user_subject_provider"),
    )

    id: int | None = Field(default=None, primary_key=True)
    identity_id: int = Field(index=True)
    provider_id: str = Field(index=True)
    email: EmailStr = Field()
    subject: str = Field()
    access_token_encrypted: str = Field()
    refresh_token_encrypted: Optional[str] = Field(default=None)
    token_type: str = Field(default="Bearer")
    expires_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True)),
    )
    scopes_granted: List[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String)),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )

    @property
    def access_token(self) -> str:
        return decrypt_field(self.access_token_encrypted)

    @access_token.setter
    def access_token(self, value: str):
        self.access_token_encrypted = encrypt_field(value)

    @property
    def refresh_token(self) -> Optional[str]:
        if self.refresh_token_encrypted:
            return decrypt_field(self.refresh_token_encrypted)
        return None

    @refresh_token.setter
    def refresh_token(self, value: Optional[str]):
        if value:
            self.refresh_token_encrypted = encrypt_field(value)
        else:
            self.refresh_token_encrypted = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @classmethod
    def get(
        cls,
        session: Session,
        token_id: int
    ) -> Optional["ExternalToken"]:
        statement = select(cls).where(
            cls.id == token_id
        )
        return session.exec(statement).first()

    @classmethod
    def upsert(
        cls,
        session: Session,
        identity_id: int,
        provider_id: str,
        access_token: str,
        refresh_token: Optional[str],
        token_type: str,
        expires_at: Optional[datetime],
        scopes_granted: List[str],
        subject: str,
        email: EmailStr
    ) -> "ExternalToken":
        existing = cls.get_by_id_sub(session, identity_id, provider_id, subject)
        if existing:
            existing.access_token_encrypted = encrypt_field(access_token)
            if refresh_token:
                existing.refresh_token_encrypted = encrypt_field(refresh_token)
            existing.token_type = token_type
            existing.expires_at = expires_at
            existing.scopes_granted = scopes_granted
            existing.updated_at = datetime.now(timezone.utc)
            session.add(existing)
            session.commit()
            session.refresh(existing)
            return existing

        token = cls(
            identity_id=identity_id,
            provider_id=provider_id,
            subject=subject,
            access_token_encrypted=encrypt_field(access_token),
            refresh_token_encrypted=encrypt_field(refresh_token) if refresh_token else None,
            token_type=token_type,
            expires_at=expires_at,
            scopes_granted=scopes_granted,
        )
        session.add(token)
        session.commit()
        session.refresh(token)
        return token
    
    @classmethod
    def get_by_id_sub(
        cls,
        session: Session,
        identity_id: int,
        provider_id: str,
        subject: str
    ):
        statement = select(cls).where(
            cls.identity_id == identity_id,
            cls.provider_id == provider_id,
            cls.subject == subject
        )
        return session.exec(statement).first()

    @classmethod
    def get_all_for_user(
        cls,
        session: Session,
        identity_id: int,
    ) -> list["ExternalToken"]:
        statement = select(cls).where(
            cls.identity_id == identity_id
        )
        return list(session.exec(statement).all())

    @classmethod
    def get_all_for_user_by_provider(
        cls,
        session: Session,
        identity_id: int,
        provider_id: str
    ) -> list["ExternalToken"]:
        statement = select(cls).where(
            cls.identity_id == identity_id,
            cls.provider_id == provider_id,
        )
        return list(session.exec(statement).all())

    @classmethod
    def get_all_for_provider(cls, session: Session, provider_id: str) -> list["ExternalToken"]:
        statement = select(cls).where(cls.provider_id == provider_id)
        return list(session.exec(statement).all())
