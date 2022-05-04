"""Serialization utilities."""

from io import BufferedReader, BufferedWriter
from typing import TypeVar, Callable, List, Any, Optional

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


class MemorySerializer(BufferedWriter):
    def __init__(self):
        self._blob = b''

    def write(self, s: Any) -> int:
        self._blob += s
        return len(s)

    def bytes(self) -> bytearray:
        return self._blob


class MemoryDeserializer(BufferedReader):
    def __init__(self, s: bytes):
        self._blob = s
        self._cursor = 0

    def read(self, n: Optional[int] = 0) -> bytes:
        n = n or 0
        data = self._blob[self._cursor:(self._cursor + n)]
        self._cursor += n
        return data


class ConnectionClosed(Exception):
    """Raised when a connection closes when we're reading data."""
