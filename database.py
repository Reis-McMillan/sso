from sqlmodel import create_engine, Session, SQLModel
from config import config

import models

engine = create_engine(config.DATABASE_URL)

def initialize_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

if __name__ == '__main__':
    initialize_db()