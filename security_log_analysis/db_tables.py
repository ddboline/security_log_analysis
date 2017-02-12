# coding: utf-8
"""
    Tables in ssh_intrusion_logs Database
"""
from sqlalchemy import (BigInteger, Column, DateTime, String)
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class HostCountry(Base):
    __tablename__ = 'host_country'

    host = Column(String(60), primary_key=True, unique=True)
    code = Column(String(2), nullable=False)


class ApacheLog(Base):
    __tablename__ = 'apache_log'

    id = Column(BigInteger, primary_key=True)
    datetime = Column(DateTime, nullable=False)
    host = Column(String(15), nullable=False)


class ApacheLogCloud(Base):
    __tablename__ = 'apache_log_cloud'

    id = Column(BigInteger, primary_key=True)
    datetime = Column(DateTime, nullable=False)
    host = Column(String(15), nullable=False)


class CountryCode(Base):
    __tablename__ = 'country_code'

    code = Column(String(2), primary_key=True, nullable=False)
    country = Column(String(50), nullable=False)


class SSHLog(Base):
    __tablename__ = 'ssh_log'

    id = Column(BigInteger, primary_key=True)
    datetime = Column(DateTime, nullable=False)
    host = Column(String(60), nullable=False)
    username = Column(String(15))


class SSHLogCloud(Base):
    __tablename__ = 'ssh_log_cloud'

    id = Column(BigInteger, primary_key=True)
    datetime = Column(DateTime, nullable=False)
    host = Column(String(60), nullable=False)
    username = Column(String(15))


def create_tables(engine):
    Base.metadata.create_all(bind=engine)


def delete_tables(engine):
    Base.metadata.drop_all(bind=engine)
