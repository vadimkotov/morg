from sqlalchemy import Column, ForeignKey, Integer, String, Text, Boolean, Binary
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import exists

DB_PROTO = "sqlite"

class File(Base):
    __tablename__ = "file"
    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), nullable=False, unique=True)

class Magic(Base):
    __tablename__ = "magic"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("file.id"))
    magic_str = Column(Text)
    file = relationship(File)


class PE(Base):
    __tablename__ = "pe"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("file.id"))
    machine_type = Column(Integer)
    dotnet = Column(Boolean)
    
    file = relationship(File)

class UPX(Base):
    __tablename__ = "upx"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("file.id"))
    result = Column(Boolean)
        
    file = relationship(File)


class IDA_CFG(Base):
    __tablename__ = "ida_cfg"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("file.id"))
    data = Column(Binary)
        
    file = relationship(File)

class PE_Features_1(Base):
    __tablename__ = "pe_features_1"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("file.id"))
    data = Column(Binary)

    file = relationship(File)


    
def get_engine(conn_str):
    return create_engine("{}:///{}".format(DB_PROTO, conn_str))
    
def init_db(conn_str):
    engine = get_engine(conn_str)
    Base.metadata.create_all(engine)


def connect(conn_str):
    engine = get_engine(conn_str)
    Session = sessionmaker(bind=engine)
    return Session()
    
# def file_exists(session, sha256):
#     return session.query(exists().where(File.sha256==sha256)).scalar()

def record_exists(session, Table, file_):
    # return session.query(exists().where(Table.file=file_)).scalar()
    return session.query(Table).filter_by(file_id=file_.id).first() != None

def file_by_sha256(session, sha256):
    return session.query(File).filter_by(sha256=sha256).first()

def add_file(session, sha256):
    file_ = File(sha256=sha256)
    session.add(file_)
    session.commit()
    return file_
