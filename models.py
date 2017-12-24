from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime


Base = declarative_base()


class User(Base):
    """Represent user info"""

    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class CatalogCategory(Base):
    """Represent catalog table"""

    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(30), nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }


class Item(Base):
    """Represent item in each category"""

    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    title = Column(String(30), nullable=False)
    description = Column(String(500))
    created_datetime = Column(DateTime, default=datetime.datetime.utcnow)
    cat_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(CatalogCategory)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'cat_id': self.cat_id,
            'description': self.description,
            'id': self.id,
            'title': self.title
        }


class InitTable(Base):
    """Represent initialization state of the database"""

    __tablename__ = 'init_table'
    id = Column(Integer, primary_key=True)
    initialized = Column(Boolean, default=False)


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
