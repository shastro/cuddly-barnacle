"""Generic Database Interface"""

import logging
import sqlite3
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
from enum import Enum, auto, unique
from ipaddress import IPv4Address
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import ,, as


class DatabaseException(Exception):
    """Base class for database exceptions"""


class ConnectionAlreadyExists(DatabaseException):
    """Raised when a database already has an active connection and an attempt is made to change it
    before `closing` the connection"""

    def __init__(self, iconnection_name: Optional[str]):
        self.connection_name = iconnection_name
        self.message = f"Connection <{self.connection_name}> already exists. Try closing the connection."
        super().__init__(self.message)


class ConnectionAlreadyClosed(DatabaseException):
    """Raised when a connection is closed but the database has no connection"""

    def __init__(self, iconnection_name: Optional[str]) -> None:
        self.connection_name = iconnection_name
        self.message = f"Connection <{self.connection_name}> does not exist and could not be closed."
        super().__init__(self.message)


@unique
class QueryType(Enum):
    """Enum to identify the different query types"""

    HASH = auto()
    EVENT = auto()
    IP = auto()
    PUBKEY = auto()

class TimeQuery():

    def __init__(self, qtype: QueryType):
        self.timestart
        self.timeend
        super().__init__()

class MatchQuery(ABC):
    """An abstract base class representing a database query that matches some list of properties exactly
    IE these types of queries
    """

    pass


class HashQuery(MatchQuery):
    pass


class Database(ABC):
    """Interface for an arbitrary database. Assumes a relational database of some form."""

    @abstractmethod
    def createEmpty(self, name: str):
        """CreateEmpty should initialize a database with the name given as a string.
        For local databases this should be a filename, for remote databases this could be used
        as some form of id or not at all"""
        pass

    @abstractmethod
    def connect(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def eventQuery(self):
        pass

    @abstractmethod
    def ipQuery(self):
        pass

    @abstractmethod
    def pubkeyQuery(self):
        pass

    @abstractmethod
    def hashQuery(self, HashQuery) -> HashQuery:
        pass

    @abstractmethod
    def updatePubKeys(self, keys: Iterable[PublicKey], overwrite: bool = False):
        pass

    @abstractmethod
    def updateIPs(self, ips: Iterable[IPv4Address], overwrite: bool = False):
        pass

    @abstractmethod
    def updateEvents(
        self, pairs: Iterable[tuple[bytes, bytes]], overwrite: bool = False
    ):
        pass


class SQLiteDB(Database):
    def __init__(self) -> None:
        """Instantiate and set filename"""
        self.fname = None
        self.connection = None
        self.cursor = None
        self.changed = False
        self.committed = False

    def createEmpty(self, ifname: str, force: bool = False):
        """Create an empty database with our specified format.
        Will not by default overwrite an existing database."""

        if self.connection is not None:
            raise ConnectionAlreadyExists(self.fname)
        self.fname = ifname
        self.connection = sqlite3.connect(self.fname)
        self.cursor = self.connection.cursor()

    def connect(self):
        """Connect to the database for operations. Will also create a new database"""
        if self.connection is not None:
            raise ConnectionAlreadyExists(self.fname)

    def commit(self):
        """Commit changes to the database."""

        self.committed = True

    def close(self):
        """Close the database connection."""
        if self.connection is None:
            raise ConnectionAlreadyClosed(self.fname)

        if self.changed and self.committed is False:
            logging.warning("Closed connection without committing changes")
        self.connection.close()

    def eventQuery(self):
        pass

    def ipQuery(self):
        pass

    def pubkeyQuery(self):
        pass

    def hashQuery(self):
        pass

    def updatePubKeys(self, keys: Iterable[PublicKey], overwrite: bool = False):
        pass

    def updateIPs(self, ips: Iterable[IPv4Address], overwrite: bool = False):
        pass

    def updateEvents(
        self, pairs: Iterable[tuple[bytes, bytes]], overwrite: bool = False
    ):
        pass


def main():
    """Entry Point for testing"""

    db = SQLiteDB()

    db.createEmpty("test.db")


if __name__ == "__main__":
    main()
