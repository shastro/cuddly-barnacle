"""SQLite Database Interface abstraction over sqlite3

This file implements the database interface for the application data on the
system. Typically stored under ~/.chatchat/database [Defined in Environment.py]

This system is interfaced with the synchronization system as well as the frontend.


The structure of the database is as follows

Accepted IP table
-----------------
Table Name: peers
Description of Items
- IP addr - port to try - Last seen timestamp - trust flag
True Names and Types
- addr: TEXT - port: INTEGER - timestamp: REAL - trust: INTEGER

Accepted PubKey Table
-----------------
Table Name: keys
- PubKey - Last seen time stamp - trust flag
- publickey: TEXT - timestamp: REAL - trust: INTEGER

Event Table
-----------------
Table Name: events
- recv timestamp - event hash - event  blob encoded as bytes
- timestamp: REAL - hash: TEXT - event: BLOB

We store trust flags since we might want to know who is banned or not.

"""
import datetime
import hashlib
import logging
import sqlite3
from types import NoneType
import unittest
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
from enum import Enum, auto, unique
import os
from os import path
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
from EncryptedStream import PrivateKey, PublicKey, PeerAddress, Encoding, PublicFormat
from Environment import Env

# Globals
env = Env()
# Generic Type Var
T = TypeVar("T")
DateTime = datetime.datetime

# Global Vars
PEER_TABLE = "peers"
EVENT_TABLE = "events"
KEY_TABLE = "keys"


@unique
class Tables(Enum):
    """Enum to represent the table names that are possible"""

    PEER_TABLE = PEER_TABLE
    EVENT_TABLE = EVENT_TABLE
    KEY_TABLE = KEY_TABLE


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


def where_gen(kwargs) -> str:
    """Utility function for generating where cases given a tuple of items to match"""
    base = ""
    items = list(kwargs.items())
    for k, v in items[:-1]:
        base += f"('{k}' = {v}) AND "

    k, v = items[-1]
    base += f"('{k}' = {v})"

    return base


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

    @abstractclassmethod
    def get_item_type():
        """Function to return the associated object for each selector

        :returns: A reference to a python object

        """
        pass

    @abstractclassmethod
    def get_table_name() -> str:
        """Function to return the table name from which the selector selects from

        :returns: str table name

        """
        pass


class HashSelector(DatabaseSelector):
    """Class representing a query to the database looking for matches on other
    properties that match the list of hashes.

    Useful for selecting the list of blobs that match the given list of hashes.
    """

    def __init__(self, hashes: Optional[List[str]]):
        self._hashes = hashes
        self._table_name = EVENT_TABLE
        self._query = SQLQuery(self._table_name)
        self._item_type = EventItem

    def get_query(self):
        """Get the query associated with HashSelector

        :returns: SQLQuery object

        """
        if self._hashes == None:
            return self._query

        if len(self._hashes) == 0:
            return self._query.where("hash IN ()")

        base = "hash IN ("
        for h in self._hashes[:-1]:
            base += f"'{h}',"

        base += f"'{self._hashes[-1]}')"
        self._query.where(base)
        return self._query

    def get_item_type(self):
        return self._item_type

    def get_table_name(self):
        return self._table_name


class PeerSelector(DatabaseSelector):
    """Class that will produce selections on the peers"""

    def __init__(self, peers: Optional[List[PeerAddress]]):
        """Create a new PeerSelector

        :param peers: List of peers to match against. Passing None will query
        for ALL peers. Passing an empty array will return nothing. :returns:
        None

        """
        self._peers = peers
        self._table_name = PEER_TABLE
        self._query = SQLQuery(self._table_name)
        self._item_type = PeerItem

    def get_query(self):
        """Get the query associated with PeerSelector

        :returns: SQLQuery object

        """
        if self._peers == None:
            return self._query

        if len(self._peers) == 0:
            return self._query.where("peer IN ()")

        addrclause = ""
        for p in self._peers[:-1]:
            addrclause += f"(addr = '{p[0]}' AND port = {p[1]}) OR "

        p = self._peers[-1]
        addrclause += f"(addr = '{p[0]}' AND port = {p[1]})"
        self._query.where(addrclause)

        return self._query

    def get_item_type(self):
        return self._item_type

    def get_table_name(self):
        return self._table_name


class PubKeySelector(DatabaseSelector):
    def __init__(self, keys: Optional[List[str]]):
        """Create a new PublicKeySelector

        This will match against publickeys in the provided list. Providing
        `None` will select all available publickeys. To get only the trusted
        keys please used a `TrustSelector` decorator.

        :param keys: List of publickeys to match against
        :returns:

        """
        self._keys = keys
        self._table_name = KEY_TABLE
        self._query = SQLQuery(self._table_name)
        self._item_type = PubKeyItem

    def get_query(self):

        if self._keys == None:
            return self._query

        if len(self._keys) == 0:
            return self._query.where("publickey IN ()")

        base = "publickey IN ("
        for h in self._keys[:-1]:
            base += f"'{h}',"
        base += f"'{self._keys[-1]}')"

        self._query.where(base)
        return self._query

    def get_item_type(self):
        return self._item_type

    def get_table_name(self):
        return self._table_name


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
        self._item_type = self._cls.get_item_type()
        self._table_name = self._cls.get_table_name()

    def get_query(self):
        tstart = self._start.timestamp()
        tend = self._end.timestamp()

        return (
            self._cls.get_query()
            .where(f"timestamp >= {tstart}")
            .where(f"timestamp <= {tend}")
        )

    def get_item_type(self):
        return self._item_type

    def get_table_name(self):
        return self._table_name


# DecoratorClass
class TrustSelector(DatabaseSelector):
    """TrustSelector is a decorator class over a normal query.

    It can be used to filter the data written to or returned from the database
    to select across the trusted property.

    """

    def __init__(self, cls: DatabaseSelector, trust: bool):
        self._cls = cls
        if type(self._cls) == HashSelector:
            raise TypeError("Cannot use TrustSelector on HashSelector")
        self._property = "timestamp"
        self._trust = int(trust)
        self._item_type = self._cls.get_item_type()
        self._table_name = self._cls.get_table_name()

    def get_query(self):
        return self._cls.get_query().where(f"trust = {self._trust}")

    def get_item_type(self):
        return self._item_type

    def get_table_name(self):
        return self._table_name


# Database API Ideas
# db.query(TimeFilter(PubKeySelector(None))) Returns everything every PubKeyItem
# db.query(TimeFilter(PubKeySelector([]))) Returns no items


class DatabaseItem(ABC):
    """Abstract Base Class for database items"""

    @abstractmethod
    def serialize():
        pass

    @abstractmethod
    def deserialize():
        pass

    @abstractmethod
    def as_dict() -> dict:  # type: ignore
        pass

    @abstractmethod
    def get_table_name():
        pass


class EventItem(DatabaseItem):
    """EventItem, represents a row in the event table"""

    def __init__(self, timestamp: DateTime, hash: str, blob: bytearray):
        """Create a new EventItem.

        :param timestamp: DateTime object representing the timestamp of the event
        :param hash: string representing the hexdigest of the hash
        :param blob: bytearray representing the blob bytes
        :returns:

        """
        self._table_name = EVENT_TABLE
        self._blob = blob
        self._hash = hash
        self._timestamp = timestamp.timestamp()

    def serialize(self):
        return (self._timestamp, str(self._hash), bytes(self._blob))

    def as_dict(self) -> dict:
        return {
            "timestamp": float(self._timestamp),
            "hash": f"'{str(self._hash)}'",
            "event": bytes(self._blob),
        }

    @staticmethod
    def deserialize(timestamp: float, hash: str, event: bytes):
        return EventItem(
            datetime.datetime.fromtimestamp(timestamp), hash, bytearray(event)
        )

    def get_table_name(self):
        return self._table_name


class PeerItem(DatabaseItem):
    """PeerItem, represents a row in the peers table"""

    def __init__(self, addr: str, port: int, timestamp: DateTime, trust: bool):
        self._table_name = PEER_TABLE
        self._addr = addr
        self._port = port
        self._timestamp = timestamp.timestamp()
        self._trust = trust

    def serialize(self):
        return (self._addr, int(self._port), self._timestamp, int(self._trust))

    def as_dict(self) -> dict:
        return {
            "addr": f"'{str(self._addr)}'",
            "port": int(self._port),
            "timestamp": self._timestamp,
            "trust": int(self._trust),
        }

    @staticmethod
    def deserialize(addr: str, port: int, timestamp: float, trust: int) -> "PeerItem":
        return PeerItem(
            addr, port, datetime.datetime.fromtimestamp(timestamp), bool(trust)
        )

    def get_table_name(self):
        return self._table_name


class PubKeyItem(DatabaseItem):
    """PublicKeyItem, represents a row in the pubkey table"""

    def __init__(self, key: str, timestamp: DateTime, trust: bool):
        """Create a new public key item

        :param key: hex string encoding of the publickey
        :param timestamp: DateTime object representing the last seen timestamp of the key
        :param trust: boolean trust flag
        :returns: None

        """
        self._table_name = KEY_TABLE
        self._key = key
        self._table_name = "keys"
        self._timestamp = timestamp.timestamp()
        self._trust = trust

    def serialize(self) -> Tuple:
        """Serializes the row into a tuple ready to be inserted using sqlite3 cursors

        :returns: tuple representation.

        """
        return (str(self._key), int(self._timestamp), int(self._trust))

    def as_dict(self) -> dict:
        return {
            "publickey": f"'{self._key}'",
            "timestamp": int(self._timestamp),
            "trust": int(self._trust),
        }

    @staticmethod
    def deserialize(key: str, timestamp: float, trust: int) -> "PubKeyItem":
        """Produces a PubKeyItem object given the raw output from sql"""
        return PubKeyItem(key, datetime.datetime.fromtimestamp(timestamp), bool(trust))

    def get_table_name(self):
        return self._table_name


class SQLiteDB:
    """SQLiteDB abstraction over the sqlite3 interface.

    Designed to be used with our system and supportsthe specific kinds of
    queries we are interested in.

    """

    def __init__(self, dbpath: PurePath) -> None:
        """Instantiate and set filename"""
        self.fname = dbpath
        self.connection = None
        self.cursor = None
        self.changed = False
        self.committed = False

    def createEmpty(self, force: bool = False):
        """Create an empty database with our specified format.

        Will not by default overwrite an existing database unless the `force`
        flag is specified. This function establishes connection to the sqlite3
        file and creates a cursor object.

        """

        if self.connection is not None:
            raise ConnectionAlreadyExists(self.fname.as_posix())  # type: ignore

        if self.fname is not None:
            if force:
                if os.path.exists(self.fname.as_posix()):
                    os.remove(self.fname.as_posix())
                self.connection = sqlite3.connect(self.fname.as_posix())  # type: ignore
                self.cursor = self.connection.cursor()
                self.cursor.execute(
                    "CREATE TABLE peers(addr TEXT NOT NULL, port INTEGER NOT NULL, timestamp REAL NOT NULL, trust INTEGER NOT NULL);"
                )

                self.cursor.execute(
                    "CREATE TABLE keys(publickey TEXT NOT NULL, timestamp REAL NOT NULL, trust INTEGER NOT NULL);"
                )

                self.cursor.execute(
                    "CREATE TABLE events(timestamp REAL NOT NULL, hash TEXT NOT NULL, event BLOB NOT NULL);"
                )

        self.connection = sqlite3.connect(self.fname.as_posix())  # type: ignore
        self.cursor = self.connection.cursor()

    def connect(self):
        """Connect to the database for operations. Will not create a new database"""
        if self.connection is not None:
            raise ConnectionAlreadyExists(self.fname.as_posix())  # type: ignore

        try:
            self.connection = sqlite3.connect(self.fname.as_posix())
        except Exception:
            raise ConnectionError(self.fname.as_posix())

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
        self.connection = None

    def query(self, select: DatabaseSelector) -> List[DatabaseItem]:
        """Return the requested information based on a query type, which may be decorated.

        Returns a list of DatabaseItems, each representing a row in the database
        """

        rescursor = self.cursor.execute(select.get_query().get_str())  # type: ignore

        ItemType = select.get_item_type()
        if ItemType == None:
            raise DatabaseException("ItemType cannot be None")

        dbitems = []
        for item in rescursor.fetchall():
            dbitems.append(ItemType.deserialize(*item))

        return dbitems
        # raise InvalidQuery("Invalid Query Type in Function eventQuery")

    def write(
        self,
        items: List[DatabaseItem],
        write_type: WriteType = WriteType.APPEND,
        table_name: Optional[Union[Tables, str]] = None,
    ):
        """Will write the input item to the database using the specified WriteMode

        Will append by default. If you wish to delete everything from a table pass an empty list to the argument keys and specify a table name in the optional table_name argument

        """
        if table_name is not None:
            if type(table_name) == Tables:
                table_name = table_name.value

        if items is None:
            raise WriteError("Cannot write None into database")

        if self.cursor == None:
            raise WriteError("Cursor is None in write()")

        if write_type == WriteType.APPEND:
            """Can just insert into the database"""

            # Cannot insert 0 items
            if len(items) == 0:
                return

            for item in items:
                self.cursor.execute(  # type: ignore
                    f"INSERT INTO {item.get_table_name()} VALUES ({'?,'*(len(item.serialize())-1)}?);",  # type:ignore
                    item.serialize(),  # type: ignore
                )  # type: ignore

        elif write_type == WriteType.SYNC:
            """Need table name to synchronize without a table name"""
            if table_name is None:
                raise WriteError("Cannot SYNC without specifying a table name")

            # Delete from table
            self.cursor.execute(f"DELETE FROM {table_name}")
            for item in items:
                if item.get_table_name() != table_name:
                    raise WriteError(
                        f"Cannot synchronize multiple item types on mismatching table name. Tried to delete from {table_name} on object from {item.get_table_name()}"
                    )

                self.cursor.execute(  # type: ignore
                    f"INSERT INTO {item.get_table_name()} VALUES ({'?,'*(len(item.serialize())-1)}?);",  # type:ignore
                    item.serialize(),  # type: ignore
                )  # type: ignore

        elif write_type == WriteType.DELETE:
            """Delete no items from the database if you pass an empty list"""
            if len(items) == 0:
                return None
            else:
                """Delete the specified items from the database"""
                for item in items:
                    self.cursor.execute(
                        f"DELETE FROM {item.get_table_name()} WHERE {where_gen(item.as_dict())}"
                    )

        self.cursor.execute("COMMIT")


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


class ConnectionError(DatabaseException):
    """Raised when a connection could not be made. Have you created a database?"""

    def __init__(self, iconnection_name: Optional[str]) -> None:
        self.connection_name = iconnection_name
        self.message = f"Connection <{self.connection_name}> does not exist."
        super().__init__(self.message)


class WriteError(DatabaseException):
    """Raised when a write could not be made. Have you created a database?"""

    def __init__(self, reason: Optional[str]) -> None:
        self.message = f"Write could not be made: {reason}"
        super().__init__(self.message)


###########
# TESTING #
###########
class TestDataBase(unittest.TestCase):
    def test_utils(self):
        self.assertEqual(
            "('thing1' = 1) AND ('thing2' = 2) AND ('thing3' = 3)",
            where_gen({"thing1": 1, "thing2": 2, "thing3": 3}),
        )

    def test_write_sync(self):
        env = Env()
        db = SQLiteDB(env.get_database_path())
        db.createEmpty(force=True)

        # Test None
        into_items = None
        with self.assertRaises(WriteError):
            db.write(into_items, WriteType.SYNC)  # type: ignore

        into_items = []
        # Test Empty
        into_items.append(
            PeerItem("192.168.32.32", 6969, datetime.datetime.now(), True)
        )
        # Append some data first to test deletion
        db.write(
            into_items,
            WriteType.APPEND,
        )
        db.write([], WriteType.SYNC, Tables.PEER_TABLE)
        out_items = db.query(PeerSelector(None))
        self.assertCountEqual([], out_items)

        # Test Single
        into_items = []
        into_items.append(
            PeerItem("192.168.32.32", 6969, datetime.datetime.now(), True)
        )
        with self.assertRaises(WriteError):
            db.write(into_items, WriteType.SYNC, Tables.KEY_TABLE)

        db.write(into_items, WriteType.SYNC, Tables.PEER_TABLE)
        out_items = db.query(PeerSelector(None))
        for inp, outp in zip(into_items, out_items):
            self.assertEqual(inp.as_dict(), outp.as_dict())

        # Test Multiple
        # Reset since python lists allow duplicates
        into_items = []
        db.close()
        db.createEmpty(force=True)

        into_items.append(
            PeerItem("192.100.100.100", 6000, datetime.datetime.now(), True)
        )
        into_items.append(PeerItem("192.0.0.0", 1000, datetime.datetime.now(), False))

        # Add items
        db.write(into_items, WriteType.APPEND)
        # Erase first item
        db.write([into_items[-1]], WriteType.SYNC, into_items[-1].get_table_name())
        out_items = db.query(PeerSelector(None))

        A = [into_items[-1].serialize()]
        B = [b.serialize() for b in out_items]
        # print(A, B)
        self.assertCountEqual(
            A, B
        )  # Actually tests that lists are the same regardless of order

        # Test Multiple Types
        db.close()
        db.createEmpty(force=True)

        h = hashlib.sha256()
        h.update(b"bruh")
        h = h.hexdigest()
        into_items.append(
            EventItem(datetime.datetime.now(), h, bytearray([69, 69, 69, 69]))
        )

        db.write(into_items, WriteType.APPEND)
        db.write([], WriteType.SYNC, Tables.PEER_TABLE)

        out_items = db.query(PeerSelector(None))
        out_items += db.query(HashSelector(None))

        A = [into_items[-1].serialize()]
        B = [b.serialize() for b in out_items]

        self.assertCountEqual(
            A, B
        )  # Actually tests that lists are the same regardless of order

        # Key Test
        into_items = []
        key = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()

        a = [key]
        sel = PubKeySelector(a)  # type: ignore

        into_items = [PubKeyItem(key, datetime.datetime.now(), False)]
        db.write(into_items, WriteType.SYNC, Tables.KEY_TABLE)  # type: ignore
        out_items = db.query(TrustSelector(PubKeySelector(a), True))
        self.assertCountEqual([], out_items)
        out_items = db.query(TrustSelector(PubKeySelector(a), False))

        A = [a.serialize() for a in into_items]
        B = [b.serialize() for b in out_items]

        self.assertCountEqual(
            A, B
        )  # Actually tests that lists are the same regardless of order

    def test_write_append(self):
        env = Env()
        db = SQLiteDB(env.get_database_path())
        db.createEmpty(force=True)

        # Test None
        into_items = None
        with self.assertRaises(WriteError):
            db.write(into_items, WriteType.APPEND)  # type: ignore

        # Test Empty
        into_items = []
        db.write(into_items, WriteType.APPEND)

        # Test Single
        into_items.append(
            PeerItem("192.168.32.32", 6969, datetime.datetime.now(), True)
        )
        db.write(
            into_items,
            WriteType.APPEND,
        )
        out_items = db.query(PeerSelector(None))
        for inp, outp in zip(into_items, out_items):
            self.assertEqual(inp.as_dict(), outp.as_dict())

        # Test Multiple
        # Reset since python lists allow duplicates
        into_items = []
        db.close()
        db.createEmpty(force=True)

        into_items.append(
            PeerItem("192.100.100.100", 6000, datetime.datetime.now(), True)
        )
        into_items.append(PeerItem("192.0.0.0", 1000, datetime.datetime.now(), False))

        db.write(
            into_items,
            WriteType.APPEND,
        )
        out_items = db.query(PeerSelector(None))

        A = [a.serialize() for a in into_items]
        B = [b.serialize() for b in out_items]
        self.assertCountEqual(
            A, B
        )  # Actually tests that lists are the same regardless of order

        # Test Multiple Types
        db.close()
        db.createEmpty(force=True)

        h = hashlib.sha256()
        h.update(b"bruh")
        h = h.hexdigest()
        into_items.append(
            EventItem(datetime.datetime.now(), h, bytearray([69, 69, 69, 69]))
        )

        db.write(into_items, WriteType.APPEND)

        out_items = db.query(PeerSelector(None))
        out_items += db.query(HashSelector(None))

        A = [a.serialize() for a in into_items]
        B = [b.serialize() for b in out_items]

        self.assertCountEqual(
            A, B
        )  # Actually tests that lists are the same regardless of order

        # Test Key
        key = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()

        a = [key]
        sel = PubKeySelector(a)  # type: ignore

        into_items = [PubKeyItem(key, datetime.datetime.now(), True)]
        db.write(into_items, WriteType.APPEND)  # type: ignore
        out_items = db.query(PubKeySelector(a))
        print(into_items)

        A = [a.serialize() for a in into_items]
        B = [b.serialize() for b in out_items]

        self.assertCountEqual(
            A, B
        )  # Actually tests that lists are the same regardless of order


class TestSQLQuery(unittest.TestCase):
    def test_no_where(self):
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

        # Test None
        sel = HashSelector(None)
        q = sel.get_query()
        self.assertEqual("SELECT * FROM events;", q.get_str())

        # Test Empty
        sel = HashSelector([])
        q = sel.get_query()
        self.assertEqual("SELECT * FROM events WHERE hash IN ();", q.get_str())

        # Test Single
        a, b, c = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
        a.update(b"test1")
        adigest = a.hexdigest()

        sel = HashSelector([adigest])
        q = sel.get_query()
        self.assertEqual(
            f"SELECT * FROM events WHERE hash IN ('{adigest}');",
            q.get_str(),
        )
        # Test Multiple
        b.update(b"test2")
        c.update(b"test3")

        bdigest = b.hexdigest()
        cdigest = c.hexdigest()

        sel = HashSelector([adigest, bdigest, cdigest])
        q = sel.get_query()
        self.maxDiff = None

        self.assertEqual(
            f"SELECT * FROM events WHERE hash IN ('{adigest}','{bdigest}','{cdigest}');",
            q.get_str(),
        )

    def test_peer_selector(self):

        # Test None
        sel = PeerSelector(None)
        q = sel.get_query()
        self.assertEqual("SELECT * FROM peers;", q.get_str())

        # Test Empty
        sel = PeerSelector([])
        q = sel.get_query()
        self.assertEqual("SELECT * FROM peers WHERE peer IN ();", q.get_str())

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

    def test_key_selector(self):

        # Test None
        sel = PubKeySelector(None)
        q = sel.get_query()
        self.assertEqual("SELECT * FROM keys;", q.get_str())

        # Test Empty
        sel = PubKeySelector([])
        q = sel.get_query()
        self.assertEqual("SELECT * FROM keys WHERE publickey IN ();", q.get_str())

        # Test Single
        key = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()

        a = [key]
        sel = PubKeySelector(a)  # type: ignore
        self.assertEqual(
            f"SELECT * FROM keys WHERE publickey IN ('{key}');",
            sel.get_query().get_str(),
        )

        # Test Multiple
        key2 = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()
        key3 = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()
        a.append(key2)
        a.append(key3)

        sel = PubKeySelector(a)  # type: ignore
        self.assertEqual(
            f"SELECT * FROM keys WHERE publickey IN ('{key}','{key2}','{key3}');",
            sel.get_query().get_str(),
        )

    def test_time_selector(self):

        # Test None
        start = datetime.datetime(2009, 10, 20, hour=0, minute=39, second=0)
        end = datetime.datetime.now()
        sel = TimeSelector(PubKeySelector(None), start, end)
        q = sel.get_query()

        wherestr = (
            f"timestamp >= {start.timestamp()} AND timestamp <= {end.timestamp()}"
        )
        self.assertEqual(
            f"SELECT * FROM keys WHERE {wherestr};",
            q.get_str(),
        )

        key = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()

        # Test Empty
        sel = TimeSelector(PubKeySelector([]), start, end)
        q = sel.get_query()
        self.assertEqual(
            f"SELECT * FROM keys WHERE publickey IN () AND {wherestr};",
            q.get_str(),
        )

        # Test Single
        a = [key]
        sel = TimeSelector(PubKeySelector(a), start, end)  # type: ignore
        self.assertEqual(
            f"SELECT * FROM keys WHERE publickey IN ('{key}') AND {wherestr};",
            sel.get_query().get_str(),
        )

        # Test Multiple
        key2 = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()
        key3 = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()
        a.append(key2)
        a.append(key3)
        self.maxDiff = None
        sel = TimeSelector(PubKeySelector(a), start, end)  # type: ignore
        self.assertEqual(
            f"SELECT * FROM keys WHERE publickey IN ('{key}','{key2}','{key3}') AND {wherestr};",
            sel.get_query().get_str(),
        )

    def test_trust_selector(self):

        # Test Exception
        with self.assertRaises(TypeError):
            sel = TrustSelector(HashSelector(None), True)

        # Test None
        sel = TrustSelector(PeerSelector(None), False)
        q = sel.get_query()
        self.assertEqual("SELECT * FROM peers WHERE trust = 0;", q.get_str())

        # Test Empty
        sel = TrustSelector(PeerSelector([]), True)
        q = sel.get_query()
        self.assertEqual(
            "SELECT * FROM peers WHERE peer IN () AND trust = 1;", q.get_str()
        )

        # Test PeerSelector
        a = [("192.168.13.13", 6969)]
        sel = TrustSelector(PeerSelector(a), False)
        self.assertEqual(
            "SELECT * FROM peers WHERE (addr = '192.168.13.13' AND port = 6969) AND trust = 0;",
            sel.get_query().get_str(),
        )

        # Test PubKeySelector
        key = (
            PrivateKey.generate()
            .public_key()
            .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        ).hex()

        a = [key]
        sel = TrustSelector(PubKeySelector(a), True)  # type: ignore
        self.assertEqual(
            f"SELECT * FROM keys WHERE publickey IN ('{key}') AND trust = 1;",
            sel.get_query().get_str(),
        )


def main():
    """Entry Point for testing"""
    unittest.main()


if __name__ == "__main__":
    main()
