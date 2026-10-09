from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import STATUS_COMPLETED, STATUS_OPEN, Task


class TaskNotFound(Exception):
    pass


def add_task(session: Session, user_id: UUID, title: str) -> Task:
    task = Task(user_id=user_id, title=title, status=STATUS_OPEN)
    session.add(task)
    session.flush()
    return task


def list_tasks(session: Session, user_id: UUID, status: str | None = None) -> list[Task]:
    query = select(Task).where(Task.user_id == user_id)
    if status is not None:
        query = query.where(Task.status == status)
    return list(session.scalars(query.order_by(Task.created_at)))


def complete_task(session: Session, user_id: UUID, task_id: UUID) -> Task:
    task = session.scalar(
        update(Task).where(Task.id == task_id, Task.user_id == user_id)
        .values(status=STATUS_COMPLETED).returning(Task)
    )
    if task is None:
        raise TaskNotFound("Task not found")
    return task
