from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

Base = declarative_base()

engine = create_engine('mysql://%s:%s@%s:3306/%s' % (os.environ['user'],
                                                     os.environ['password'],
                                                     os.environ['host'],
                                                     os.environ['db']),
                                                     pool_pre_ping=True)
Session = sessionmaker(bind=engine)