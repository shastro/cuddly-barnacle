"""Serialization utilities."""

from io import BufferedReader, BufferedWriter
from typing import TypeVar, Callable, List

T = TypeVar('T')


class Deserialize:
    """Container class for deserialization of standard library Python types."""

    @staticmethod
    def bytes(stream: BufferedReader) -> bytearray:
        return Deserialize._checked_read(stream, Deserialize.long(stream))

    @staticmethod
    def str(stream: BufferedReader) -> str:
        return Deserialize.bytes(stream).decode('utf-8', 'replace')

    @staticmethod
    def long(stream: BufferedReader) -> int:
        return int.from_bytes(Deserialize._checked_read(stream, 8), 'big')

    @staticmethod
    def byte(stream: BufferedReader) -> int:
        return int.from_bytes(Deserialize._checked_read(stream, 1), 'big')

    @staticmethod
    def list(
            deserializer: Callable[[BufferedReader], T],
            stream: BufferedReader,
    ) -> List[T]:
        n_items = Deserialize.long(stream)
        items = []
        for _ in range(n_items):
            items.append(deserializer(stream))

        return items

    @staticmethod
    def _checked_read(stream: BufferedReader, length: int) -> bytearray:
        data = stream.read(length)
        if len(data) < length:
            raise ConnectionClosed()

        return bytearray(data)


class Serialize:
    """Container class for serialization of """

    @staticmethod
    def bytes(stream: BufferedWriter, value: bytes) -> None:
        Serialize.long(stream, len(value))
        stream.write(value)

    @staticmethod
    def str(stream: BufferedWriter, value: str) -> None:
        Serialize.bytes(stream, value.encode('utf-8'))

    @staticmethod
    def long(stream: BufferedWriter, value: int) -> None:
        stream.write(value.to_bytes(8, 'big'))

    @staticmethod
    def byte(stream: BufferedWriter, value: int) -> None:
        stream.write(value.to_bytes(1, 'big'))

    @staticmethod
    def list(
            serializer: Callable[[BufferedWriter, T], None],
            stream: BufferedWriter,
            value: List[T]
    ) -> None:
        Serialize.long(stream, len(value))
        for item in value:
            serializer(stream, item)


class ConnectionClosed(Exception):
    """Raised when a connection closes when we're reading data."""
