from datetime import datetime, timedelta, timezone
from sqlmodel import Field, SQLModel, Session, select
from sqlalchemy import Column, DateTime
from pydantic import EmailStr, field_validator
import secrets

class Verification(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    code: int = Field()
    email_sent: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True)))
    when: datetime = Field(
        sa_column=Column(DateTime(timezone=True))
    )

    @staticmethod
    def make_code() -> int:
        return secrets.randbelow(900_000) + 100_000

    @field_validator('email', mode='before')
    @classmethod
    def transform_email(cls, v: str):
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @classmethod
    def make_entry(cls, session: Session, email: str, new_code: int):
        email = cls.transform_email(email)
        existing = session.exec(select(cls).where(cls.email == email)).first()
        if existing:
            existing.code = new_code
            existing.when = datetime.now(timezone.utc)
            session.add(existing)
            session.commit()
            session.refresh(existing)
            return existing

        db_entry = cls.model_validate({
            "email": email,
            "code": new_code,
            "when": datetime.now(timezone.utc)
        })
        session.add(db_entry)
        session.commit()
        session.refresh(db_entry)
        return db_entry

    @classmethod
    def verify(cls, session: Session, email: str, vcode: int, delta: int):
        email = cls.transform_email(email)
        expiry_limit = datetime.now(timezone.utc) - timedelta(seconds=delta)
        
        # 1. Find the record
        statement = select(cls).where(
            cls.email == email,
            cls.code == vcode,
        )
        result = session.exec(statement).first()

        if result is None:
            return None

        # check result for expiry
        # delete if expired
        if result.when < expiry_limit:
            session.delete(result)
            session.commit()
            return None

        # If found, delete it
        else:
            verified = cls.model_validate(result)
            session.delete(result)
            session.commit()
            return verified

    @classmethod
    def email_sent_at(cls, session: Session, email: str, send_dt: datetime):
        email = cls.transform_email(email)
        statement = select(cls).where(cls.email == email)
        db_entry = session.exec(statement).first()
        if db_entry:
            db_entry.email_sent = send_dt
            session.add(db_entry)
            session.commit()
            session.refresh(db_entry)
        return db_entry