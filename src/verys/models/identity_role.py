from sqlmodel import Field, SQLModel, Session, select


class IdentityRole(SQLModel, table=True):
    identity_id: int = Field(
        foreign_key='identity.id', primary_key=True, ondelete='CASCADE'
    )
    role_id: int = Field(
        foreign_key='role.id', primary_key=True, ondelete='CASCADE'
    )

    @classmethod
    def add_identity_role(
        cls,
        session: Session,
        identity_id: int,
        role_id: int,
    ):
        id_role = cls.model_validate({
            "identity_id": identity_id,
            "role_id": role_id
        })
        session.add(id_role)
        session.commit()
        session.refresh(id_role)
        return id_role

    @classmethod
    def remove_identity_role(
        cls,
        session: Session,
        identity_id: int,
        role_id: int,
    ):
        link = session.get(cls, (identity_id, role_id))
        if not link:
            return None
        session.delete(link)
        session.commit()
        return link

    @classmethod
    def list_role_identities(
        cls,
        session: Session,
        role_id: int,
    ):
        statement = select(cls.identity_id).where(cls.role_id == role_id)
        return list(session.exec(statement).all())
