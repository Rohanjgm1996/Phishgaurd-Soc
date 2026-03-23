import asyncio
from sqlalchemy import select
from passlib.context import CryptContext

from app.models.database import AsyncSessionLocal, User, init_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

async def main():
    await init_db()

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        user = result.scalar_one_or_none()

        hashed = hash_password("Admin@123")

        if user:
            user.hashed_password = hashed
            user.full_name = "SOC Administrator"
            user.role = "admin"
            user.is_active = True
            print("Admin user updated")
        else:
            user = User(
                username="admin",
                hashed_password=hashed,
                full_name="SOC Administrator",
                role="admin",
                is_active=True,
            )
            db.add(user)
            print("Admin user created")

        await db.commit()

    print("Username: admin")
    print("Password: Admin@123")

if __name__ == "__main__":
    asyncio.run(main())