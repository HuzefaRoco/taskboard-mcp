import argparse
from collections.abc import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import User
from app.security import hash_password, normalize_email


def seed(session: Session, pairs: Iterable[tuple[str, str]]) -> int:
    inserted = 0
    for email, password in pairs:
        email = normalize_email(email)
        if not email or not password:
            raise ValueError("Email and password must not be empty")
        if session.scalar(select(User).where(User.email == email)) is None:
            session.add(User(email=email, password_hash=hash_password(password)))
            inserted += 1
    session.flush()
    return inserted


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Seed users from email password pairs")
    parser.add_argument("pairs", nargs="+", metavar="EMAIL PASSWORD")
    args = parser.parse_args(argv)
    if len(args.pairs) % 2:
        parser.error("Provide an email and password for every user")
    try:
        with SessionLocal.begin() as session:
            seed(session, zip(args.pairs[::2], args.pairs[1::2]))
    except ValueError as error:
        parser.error(str(error))
    except SQLAlchemyError:
        parser.exit(1, "Unable to seed users: database operation failed\n")


if __name__ == "__main__":
    main()
