"""SQLite Database Interface abstraction over sqlite3

This file implements the database interface for the application data on the system. Typically stored under ~/.chatchat/database [Defined in Environment.py]

This system is interfaced with the synchronization system as well as the frontend.


The structure of the database is as follows

Accepted IP table
- IPv4 addr - Last seen timestamp - trust flag

Accepted PubKey Table
- PubKey - Last seen timestamp - trust flag

Event Table
- recv timestamp - event hash - event blob

We store trust flags since we might want to know who is banned or not.

"""
import datetime
import hashlib
import logging
import sqlite3
import unittest
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
from enum import Enum, auto, unique
from ipaddress import IPv4Address
from os import PathLike
from pathlib import PurePath
from sqlite3.dbapi2 import Date
from typing import (
    Any,
    Callable,
    Generic,
    Hashable,
    Iterable,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

from EncryptedStream import PrivateKey, PublicKey
from Environment import Env
from _hashlib import HASH


env = Env()
# Generic Type Var
T = TypeVar("T")
DateTime = datetime.datetime


@unique
class QueryType(Enum):
    """Enum to identify the different query types

    These represent the fields you are intending to match on.
    """

    HASH = auto()
    EVENT = auto()
    IP = auto()
    PUBKEY = auto()


@unique
class WriteType(Enum):
    """Enum to represent the kind of write operation you want to perform to the database

    DELETE - Delete all objects from the database that match the given property
    SYNC   - Sync the database contents to the list given. Delete all that do not match the set given
    APPEND - Append to the database the given set of objects
    """

    DELETE = auto()
    SYNC = auto()
    APPEND = auto()


class DatabaseSelector(ABC):
    def get_data(self) -> List[T]:  # type: ignore
        pass


class HashSelector(DatabaseSelector):
    """Class representing a query to the database looking for matches on other properties that match the list of hashes."""

    def __init__(
        self, hashes: List[HASH], start: DateTime = None, end: DateTime = None
    ):
        self._hashes = hashes
        self._time_start = start
        self._time_end = end

    def get_data(self):
        return self._hashes

    # def get_time_range(self):
    #     return (self._time_start, self._time_end)


class IPSelector(DatabaseSelector):
    def __init__(
        self, ipaddrs: List[IPv4Address], start: DateTime = None, end: DateTime = None
    ):
        self._ips = ipaddrs
        self._time_start = start
        self._time_end = end

    def get_data(self):
        return self._ips


class EventSelector(DatabaseSelector):
    def __init__(
        self, eventblobs: List[bytearray], start: DateTime = None, end: DateTime = None
    ):
        self._eventblobs = eventblobs
        self._time_start = start
        self._time_end = end

    def get_data(self):
        return self._eventblobs


class PubKeySelector(DatabaseSelector):
    def __init__(
        self, keys: List[PublicKey], start: DateTime = None, end: DateTime = None
    ):
        self._keys = keys
        self._time_start = start
        self._time_end = end

    def get_data(self):
        return self._keys


# DecoratorClass
class TimeSelector(DatabaseSelector):
    """TimeQuery is a decorator class over a normal query.

    It can be used to filter the data written to or returned from the database
    using datetime objects.

    """

    def __init__(self, cls: DatabaseSelector, start: DateTime, end: DateTime):
        self._cls = cls
        self._start = start
        self._end = end

    def get_data(self):
        return (self._cls.get_data(), self._start, self._end)


# Database API Ideas
# db.write(PubKeySelector([key1, key2, key3]), WriteType.APPEND)
# db.query(TimeFilter(PubKeySelector(None))) Returns everything every PubKeyItem
# db.query(TimeFilter(PubKeySelector([]))) Returns no items


class DatabaseItem(ABC):
    """Abstract Base Class for database items"""

    @staticmethod
    def serialize():
        pass

    def deserialize():
        pass


class PubKeyItem(DatabaseItem):
    """PublicKeyItem, represents a row in the database"""

    @staticmethod
    def serialize():
        pass


class SQLiteDB:
    """SQLiteDB abstraction over the sqlite3 interface.

    Designed to be used with our system and supportsthe specific kinds of
    queries we are interested in.

    """

    def __init__(self, dbpath: PurePath = None) -> None:
        """Instantiate and set filename"""
        self.fname = dbpath
        self.connection = None
        self.cursor = None
        self.changed = False
        self.committed = False

    def createEmpty(self, ifname: PurePath = None, force: bool = False):
        """Create an empty database with our specified format.

        Will not by default overwrite an existing database unless the `force`
        flag is specified. This function establishes connection to the sqlite3
        file and creates a cursor object.

        """

        if not self.fname:
            self.fname = ifname
        self.fname = ifname

        if self.connection is not None:
            raise ConnectionAlreadyExists(self.fname.as_posix())  # type: ignore

        self.connection = sqlite3.connect(self.fname.as_posix())  # type: ignore
        self.cursor = self.connection.cursor()

    def connect(self):
        """Connect to the database for operations. Will also create a new database"""
        if self.connection is not None:
            raise ConnectionAlreadyExists(self.fname.as_posix())  # type: ignore

    def commit(self):
        """Commit changes to the database."""

        self.committed = True

    def close(self):
        """Close the database connection."""

        if self.connection is None:
            raise ConnectionAlreadyClosed(self.fname.as_posix())  # type: ignore

        if self.changed and self.committed is False:
            logging.warning("Closed connection without committing changes")
        self.connection.close()

    def query(self, query: DatabaseSelector):
        """Return the requested information based on a query type, which may be decorated.

        Returns a databaseItem, representing a row in the database
        """
        match query:
            case HashQuery:
                print("You have a HashQuery")

            # raise InvalidQuery("Invalid Query Type in Function eventQuery")

    def write(self, keys: DatabaseSelector, write_type: WriteType = WriteType.APPEND):
        """Will write to the list of publicKeys in the database.

        Will append by default

        """
        pass


class DatabaseException(Exception):
    """Base class for database exceptions"""


class InvalidQuery(DatabaseException):
    """Raised when there is an invalid query"""

    def __init__(self, message: Optional[str]):
        self.message = message
        super().__init__(self.message)


class ConnectionAlreadyExists(DatabaseException):
    """Raised when a database already has an active connection and an attempt is made to change it
    before `closing` the connection"""

    def __init__(self, connection_name: Optional[str]):
        self.connection_name = connection_name
        self.message = f"Connection <{self.connection_name}> already exists. Try closing the connection."
        super().__init__(self.message)


class ConnectionAlreadyClosed(DatabaseException):
    """Raised when a connection is closed but the database has no connection"""

    def __init__(self, iconnection_name: Optional[str]) -> None:
        self.connection_name = iconnection_name
        self.message = f"Connection <{self.connection_name}> does not exist and could not be closed."
        super().__init__(self.message)


def main():
    """Entry Point for testing"""

    db = SQLiteDB()

    db.createEmpty(env.get_database_path())


if __name__ == "__main__":
    main()
