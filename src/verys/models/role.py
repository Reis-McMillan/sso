from typing import List, TYPE_CHECKING
from sqlmodel import Field, SQLModel, Session, select, Relationship

from verys.models.identity_role import IdentityRole

if TYPE_CHECKING:
    from verys.models.identity import Identity


class Role(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True)
    identities: List["Identity"] = Relationship(
        back_populates="roles", link_model=IdentityRole
    )

    @classmethod
    def new(
        cls,
        session: Session,
        name: str
    ):
        new_role = cls.model_validate({
            "name": name
        })
        session.add(new_role)
        session.commit()
        session.refresh(new_role)
        return new_role
    
    @classmethod
    def get(
        cls,
        session: Session,
        name: str
    ):
        statement = select(cls).where(cls.name == name)
        return session.exec(statement).first()

    @classmethod
    def delete(cls, session, name):
        role = cls.get(session, name)
        if not role:
            return None
        session.delete(role)
        session.commit()
        return role

    
    @classmethod
    def all(
        cls,
        session: Session
    ):
        statement = select(cls)
        return list(session.exec(statement).all())
    
    @classmethod
    def seed_roles(cls, session: Session):
        """Ensure standard roles exist in the database."""
        defaults = ["admin", "service-account"]
        for name in defaults:
            existing = cls.get(session, name)
            if not existing:
                session.add(cls(name=name))
        session.commit()