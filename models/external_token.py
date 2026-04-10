from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, ARRAY, String, DateTime, UniqueConstraint
from sqlmodel import Field, SQLModel, Session, select

from utils.encryption import encrypt_field, decrypt_field


class ExternalToken(SQLModel, table=True):
    __tablename__ = "external_token"
    __table_args__ = (
        UniqueConstraint("identity_email", "subject", "provider_id", name="uq_external_token_user_subject_provider"),
    )

    id: int | None = Field(default=None, primary_key=True)
    identity_email: str = Field(index=True)
    provider_id: str = Field(index=True)
    subject: Optional[str] = Field(default=None)
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
    def get(cls, session: Session, identity_email: str, provider_id: str, subject: Optional[str] = None) -> Optional["ExternalToken"]:
        statement = select(cls).where(
            cls.identity_email == identity_email,
            cls.provider_id == provider_id,
        )
        if subject is not None:
            statement = statement.where(cls.subject == subject)
        return session.exec(statement).first()

    @classmethod
    def upsert(
        cls,
        session: Session,
        identity_email: str,
        provider_id: str,
        access_token: str,
        refresh_token: Optional[str],
        token_type: str,
        expires_at: Optional[datetime],
        scopes_granted: List[str],
        subject: Optional[str] = None,
    ) -> "ExternalToken":
        existing = cls.get(session, identity_email, provider_id, subject=subject)
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
            identity_email=identity_email,
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
    def get_all_for_user(cls, session: Session, identity_email: str) -> list["ExternalToken"]:
        statement = select(cls).where(cls.identity_email == identity_email)
        return list(session.exec(statement).all())

    @classmethod
    def get_all_for_provider(cls, session: Session, provider_id: str) -> list["ExternalToken"]:
        statement = select(cls).where(cls.provider_id == provider_id)
        return list(session.exec(statement).all())
