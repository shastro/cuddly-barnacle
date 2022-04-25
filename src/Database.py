"""SQLite Database Interface abstraction over sqlite3

This file implements the database interface for the application data on the system. Typically stored under ~/.chatchat/database [Defined in Environment.py]

This system is interfaced with the synchronization system as well as the frontend.

"""
import hashlib
from _hashlib import HASH
import datetime
import logging
import sqlite3
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
from enum import Enum, auto, unique
from ipaddress import IPv4Address
from sqlite3.dbapi2 import Date
from typing import Any, Iterable, Optional, Union, List

# Project Imports
from EncryptedStream import PublicKey, PrivateKey


# @unique
# class QueryType(Enum):
#     """Enum to identify the different query types"""

#     HASH = auto()
#     EVENT = auto()
#     IP = auto()
#     PUBKEY = auto()


class TimeQuery:
    def __init__(self, start: datetime.datetime, end: datetime.datetime):
        self.time_start = start
        self.time_end = end


class HashQuery:
    def __init__(self, hashes: List[HASH]):
        self._hashes = hashes


class SQLiteDB:
    """SQLiteDB abstraction over the sqlite3 interface.

    Designed to be used with our system and supportsthe specific kinds of queries we are interested in.

    """

    def __init__(self) -> None:
        """Instantiate and set filename"""
        self.fname = None
        self.connection = None
        self.cursor = None
        self.changed = False
        self.committed = False

    def createEmpty(self, ifname: str, force: bool = False):
        """Create an empty database with our specified format.

        Will not by default overwrite an existing database unless the `force` flag is specified.
        This function establishes connection to the sqlite3 file and creates a cursor object.

        """

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

    def eventQuery(self, query: Union[TimeQuery, HashQuery]):
        """Return the requested events based on either a TimeQuery, or HashQuery

        Also returns the timing information, the associated hash, and the event blob.
        """

        if type(query) == TimeQuery:
            pass

        elif type(query) == HashQuery:
            pass

        else:
            raise InvalidQuery("Invalid Query Type in Function eventQuery")

    def ipQuery(self):
        """Return all the valid ip addresses in the database"""
        pass

    def pubkeyQuery(self):
        """Return the valid publickeys in the database"""
        pass

    def hashQuery(self):
        """Return the valid list of hashes in the database"""
        pass

    def updatePubKeys(self, keys: Iterable[PublicKey], sync: bool = False):
        """Will update the list of publicKeys in the database.

        If the sync flag is set the function will erase all the publickeys in the database and replace with the new set.

        """
        pass

    def delete_pub_keys(self, keys: Iterable[PublicKey]):
        """Delete all public keys that match those in the list `keys`"""

        pass

    def updateIPs(self, ips: Iterable[IPv4Address], overwrite: bool = False):
        """Update all the ip addresses"""
        pass

    def updateEvents(
        self, pairs: Iterable[tuple[bytes, bytes]], overwrite: bool = False
    ):
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

    db.createEmpty("test.db")


if __name__ == "__main__":
    main()
