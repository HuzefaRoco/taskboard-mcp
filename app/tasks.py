from uuid import UUID

from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from app.models import STATUS_COMPLETED, STATUS_OPEN, Task


class TaskNotFound(Exception):
    pass


def add_task(session: Session, user_id: UUID, title: str) -> Task:
    statement = (
        insert(Task).values(user_id=user_id, title=title, status=STATUS_OPEN).returning(Task)
        .execution_options(autoflush=False)
    )
    return session.scalars(statement).one()


def list_tasks(session: Session, user_id: UUID, status: str | None = None) -> list[Task]:
    query = select(Task).where(Task.user_id == user_id)
    if status is not None:
        query = query.where(Task.status == status)
    return list(session.scalars(query.order_by(Task.created_at).execution_options(autoflush=False)))


def complete_task(session: Session, user_id: UUID, task_id: UUID) -> Task:
    task = session.scalar(
        update(Task).where(Task.id == task_id, Task.user_id == user_id)
        .values(status=STATUS_COMPLETED).returning(Task)
        .execution_options(autoflush=False)
    )
    if task is None:
        raise TaskNotFound("Task not found")
    return task


def delete_task(session: Session, user_id: UUID, task_id: UUID) -> Task:
    task = session.scalars(
        delete(Task).where(Task.id == task_id, Task.user_id == user_id)
        .returning(Task)
        .execution_options(autoflush=False)
    ).one_or_none()
    if task is None:
        raise TaskNotFound("Task not found")
    return task


def update_task(
    session: Session,
    user_id: UUID,
    task_id: UUID,
    title: str | None = None,
    description: str | None = None,
) -> Task:
    values: dict[str, str] = {}
    if title is not None:
        values["title"] = title
    if description is not None:
        values["description"] = description
    if not values:
        raise ValueError("At least one of title or description is required")
    task = session.scalar(
        update(Task).where(Task.id == task_id, Task.user_id == user_id)
        .values(**values).returning(Task)
        .execution_options(autoflush=False)
    )
    if task is None:
        raise TaskNotFound("Task not found")
    return task


def reopen_task(session: Session, user_id: UUID, task_id: UUID) -> Task:
    task = session.scalar(
        update(Task).where(Task.id == task_id, Task.user_id == user_id)
        .values(status=STATUS_OPEN).returning(Task)
        .execution_options(autoflush=False)
    )
    if task is None:
        raise TaskNotFound("Task not found")
    return task


def clear_completed_tasks(session: Session, user_id: UUID) -> int:
    ids = session.scalars(
        delete(Task).where(Task.user_id == user_id, Task.status == STATUS_COMPLETED)
        .returning(Task.id)
        .execution_options(autoflush=False)
    ).all()
    return len(ids)
