"""SQLite Database Interface abstraction over sqlite3

This file implements the database interface for the application data on the system. Typically stored under ~/.chatchat/database [Defined in Environment.py]

This system is interfaced with the synchronization system as well as the frontend.


The structure of the database is as follows

Accepted IP table
Table Name: peers
Description of Items
- IP addr - port to try - Last seen timestamp - trust flag
True Names and Types
- addr: TEXT - port: INTEGER - timestamp: REAL - trust: INTEGER

Accepted PubKey Table
Table Name: keys
- PubKey - Last seen timestamp - trust flag
- publickey: TEXT - timestamp: REAL - trust: INTEGER

Event Table
Table Name: events
- recv timestamp - event hash - event blob
- timestamp: REAL - hash: TEXT - event: BLOB

We store trust flags since we might want to know who is banned or not.

"""
import datetime
import hashlib
import logging
import sqlite3
import unittest
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
from enum import Enum, auto, unique
from os import PathLike
from pathlib import PurePath
from sqlite3.dbapi2 import Date
from _hashlib import HASH
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

# Ours
from EncryptedStream import PrivateKey, PublicKey, PeerAddress
from Environment import Env


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


class SQLQuery:

    """Class representing an SQL Query. Used by selector classes to get valid SQL queries from the objects passed."""

    def __init__(self, table: str):
        """Create a new SQLQuery object

        :param table: name of table in database to query
        :returns: None

        """
        self._where_cases: List[str] = []
        self._table_name: str = table

    def where(self, condition: str):
        """Modify self to include a new where case to the list of where conditions

        :param condition: str representing a single WHERE condition
        :returns: self

        """
        self._where_cases.append(condition)
        return self

    def get_str(self):
        """Convert object into a valid SQLQuery string

        :returns: string representation of Query

        """
        base: str = f"SELECT * FROM {self._table_name}"
        if len(self._where_cases) != 0:
            base += " WHERE"

            for c in self._where_cases[:-1]:
                base += f" {c} AND"

            base += f" {self._where_cases[-1]}"

        base += ";"

        return base


class DatabaseSelector(ABC):
    """Abstract Base Class for Database Selectors"""

    @abstractmethod
    def get_query(self) -> SQLQuery:  # type: ignore
        """Function to return the SQLQuery object representing the selection choice(s)"""
        pass


class HashSelector(DatabaseSelector):
    """Class representing a query to the database looking for matches on other properties that match the list of hashes.

    Useful for selecting the list of blobs that match the given list of hashes.
    """

    def __init__(self, hashes: List[HASH]):
        self._hashes = hashes
        self._query = SQLQuery("events")

    def get_query(self):
        """Get the query associated with HashSelector

        :returns: SQLQuery object

        """
        base = "hash IN ("
        for h in self._hashes[:-1]:
            base += f"'{h.hexdigest()}',"

        base += f"'{self._hashes[-1].hexdigest()}')"
        self._query.where(base)
        return self._query


class PeerSelector(DatabaseSelector):
    """Class that will produce selections on the peers"""

    def __init__(self, peers: List[PeerAddress]):
        self._peers = peers
        self._query = SQLQuery("peers")

    def get_query(self):
        """Get the query associated with PeerSelector

        :returns: SQLQuery object

        """
        addrclause = ""
        for p in self._peers[:-1]:
            addrclause += f"(addr = '{p[0]}' AND port = {p[1]}) OR "

        p = self._peers[-1]
        addrclause += f"(addr = '{p[0]}' AND port = {p[1]})"
        self._query.where(addrclause)

        return self._query


class EventSelector(DatabaseSelector):
    def __init__(self, eventblobs: List[bytearray]):
        self._eventblobs = eventblobs

    def get_query(self):
        return self._eventblobs


class PubKeySelector(DatabaseSelector):
    def __init__(self, keys: List[PublicKey]):
        self._keys = keys

    def get_query(self):
        return self._keys


# DecoratorClass
class TimeSelector(DatabaseSelector):
    """TimeQuery is a decorator class over a normal query.

    It can be used to filter the data written to or returned from the database
    using datetime objects.

    """

    def __init__(self, cls: DatabaseSelector, start: DateTime, end: DateTime):
        self._cls = cls
        self._property = "timestamp"
        self._start = start
        self._end = end

    def get_query(self):
        tstart = self._start.timestamp()
        tend = self._end.timestamp()

        return (
            self._cls.get_query()
            .where(f"timestamp >= {tstart}")
            .where(f"timestamp <= {tend}")
        )


# Database API Ideas
# db.query(TimeFilter(PubKeySelector(None))) Returns everything every PubKeyItem
# db.query(TimeFilter(PubKeySelector([]))) Returns no items


class DatabaseItem(ABC):
    """Abstract Base Class for database items"""

    def serialize():
        pass

    @staticmethod
    def deserialize():
        pass


class EventItem(DatabaseItem):
    """EventItem, represents a row in the event table"""

    def __init__(self, blob: bytearray, hash: HASH, timestamp: DateTime):
        self._blob = blob
        self._hash = hash
        self._timestamp = timestamp

    def serialize():
        pass

    def deserialize():
        return


class IpItem(DatabaseItem):
    """IpItem, represents a row in the accepted IP table"""

    def serialize():
        pass

    @staticmethod
    def deserialize():
        pass


class PubKeyItem(DatabaseItem):
    """PublicKeyItem, represents a row in the pubkey table"""

    def serialize():
        pass

    @staticmethod
    def deserialize():
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

    def query(self, select: DatabaseSelector):
        """Return the requested information based on a query type, which may be decorated.

        Returns a databaseItem, representing a row in the database
        """
        tfilter = None
        if type(select) == TimeSelector:
            qdata, start, end = select.get_data()

            self.cursor.execute("select * from pubkey where")
            # raise InvalidQuery("Invalid Query Type in Function eventQuery")

    def write(self, keys: DatabaseItem, write_type: WriteType = WriteType.APPEND):
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


###########
# TESTING #
###########
class TestSQLQuery(unittest.TestCase):
    def test_nowhere(self):
        query = SQLQuery("ipaddrs")
        self.assertEqual(
            "SELECT * FROM ipaddrs;",
            query.get_str(),
        )

    def test_one_where(self):
        query = SQLQuery("ipaddrs").where("timestamp >= 123")
        self.assertEqual(
            "SELECT * FROM ipaddrs WHERE timestamp >= 123;",
            query.get_str(),
        )

    def test_multiple_where(self):
        query = (
            SQLQuery("ipaddrs")
            .where("timestamp >= 123")
            .where("timestamp <= 234")
            .where("hi = TEST")
        )
        self.assertEqual(
            "SELECT * FROM ipaddrs WHERE timestamp >= 123 AND timestamp <= 234 AND hi = TEST;",
            query.get_str(),
        )


class TestSelectors(unittest.TestCase):
    def test_hash_selector(self):

        # Test Single
        a, b, c = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
        a.update(b"test1")
        adigest = a.hexdigest()

        sel = HashSelector([a])
        q = sel.get_query()
        self.assertEqual(
            f"SELECT * FROM events WHERE hash IN ('{adigest}');",
            q.get_str(),
        )
        # Test Multiple
        b.update(b"test2")
        c.update(b"test3")

        sel = HashSelector([a, b, c])
        q = sel.get_query()
        bdigest = b.hexdigest()
        cdigest = c.hexdigest()
        self.maxDiff = None

        self.assertEqual(
            f"SELECT * FROM events WHERE hash IN ('{adigest}','{bdigest}','{cdigest}');",
            q.get_str(),
        )

    def test_peer_selector(self):
        # Test Single
        a = [("192.168.13.13", 6969)]
        sel = PeerSelector(a)
        self.assertEqual(
            "SELECT * FROM peers WHERE (addr = '192.168.13.13' AND port = 6969);",
            sel.get_query().get_str(),
        )

        # Test Multiple

        a.append(("192.168.14.12", 6000))  # type: ignore
        a.append(("69.69.69.69", 6969))  # type: ignore
        sel = PeerSelector(a)
        self.assertEqual(
            "SELECT * FROM peers WHERE (addr = '192.168.13.13' AND port = 6969) OR (addr = '192.168.14.12' AND port = 6000) OR (addr = '69.69.69.69' AND port = 6969);",
            sel.get_query().get_str(),
        )


def main():
    """Entry Point for testing"""
    unittest.main()


if __name__ == "__main__":
    main()
