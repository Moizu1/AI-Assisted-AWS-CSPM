import getpass
import sys

from sqlalchemy.orm import Session

from app.database.database import SessionLocal
from app.models.user import User
from app.core.security import hash_password


def create_superadmin():
    db: Session = SessionLocal()

    try:
        existing_admin = (
            db.query(User)
            .filter(User.role == "SUPER_ADMIN")
            .first()
        )

        if existing_admin:
            print("A Super Admin account already exists.")
            return

        print("\nCloudSentinel - Initial Super Admin Setup\n")

        full_name = input("Full name: ").strip()
        email = input("Email address: ").strip().lower()

        if not full_name or not email:
            print("Name and email are required.")
            return

        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords do not match.")
            return

        if len(password) < 12:
            print("Password must contain at least 12 characters.")
            return

        existing_user = (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

        if existing_user:
            print("This email address is already registered.")
            return

        superadmin = User(
            full_name=full_name,
            email=email,
            hashed_password=hash_password(password),
            role="SUPER_ADMIN",
            status="ACTIVE",
            is_two_factor_enabled=False
        )

        db.add(superadmin)
        db.commit()

        print("\nSuper Admin account created successfully.")
        print("Email:", email)
        print("Role: SUPER_ADMIN")
        print("Status: ACTIVE")
        print("\nConfigure mandatory 2FA before using the account.")

    except Exception:
        db.rollback()
        print("Super Admin creation failed.")
        raise

    finally:
        db.close()


if __name__ == "__main__":
    create_superadmin()