from uuid import UUID

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.models import Note


def add_note(session: Session, user_id: UUID, title: str, body: str) -> Note:
    statement = (
        insert(Note).values(user_id=user_id, title=title, body=body).returning(Note)
        .execution_options(autoflush=False)
    )
    return session.scalars(statement).one()


def list_notes(session: Session, user_id: UUID) -> list[Note]:
    query = select(Note).where(Note.user_id == user_id)
    return list(session.scalars(query.order_by(Note.created_at).execution_options(autoflush=False)))
