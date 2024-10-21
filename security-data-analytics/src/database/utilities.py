from sqlalchemy import create_engine
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import sessionmaker

import os

POSTGRES_USER = os.environ.get('POSTGRES_USER')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD')
POSTGRES_HOST = os.environ.get('POSTGRES_HOST')
POSTGRES_DB = os.environ.get('POSTGRES_DB')
DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:5432/{POSTGRES_DB}"

engine = None
Session = None


def init_db(url=None):
    global engine, Session
    if not engine:
        engine = create_engine(DATABASE_URL if url is None else url)
    if not Session:
        Session = sessionmaker(bind=engine)


def get_session():
    global Session
    if Session is None:
        init_db()
    session = Session()
    return session


def get_class(id, _class, session=None, raised_with_not_found_exception=False):
    if not session:
        session = get_session()
    try:
        return session.query(_class).filter_by(id=id).one()
    except NoResultFound:
        if raised_with_not_found_exception:
            raise
    except Exception as e:
        raise e
    finally:
        session.close()


def commit_object(db_object):
    global Session
    if Session is None:
        init_db()
    session = Session()
    try:
        session.add(db_object)
        session.commit()
        session.refresh(db_object)
        return db_object
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def update_object(db_object, session):
    try:
        session.merge(db_object)
        session.commit()
        session.refresh(db_object)
        session.flush()
        return db_object
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()
