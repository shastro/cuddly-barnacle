"""Serialization utilities."""

from io import BufferedReader, BufferedWriter
from typing import TypeVar, Callable, List

T = TypeVar('T')


def deserialize_bytes(stream: BufferedReader) -> bytearray:
    return bytearray(stream.read(deserialize_long(stream)))


def deserialize_str(stream: BufferedReader) -> str:
    return deserialize_bytes(stream).decode('utf-8', 'replace')


def deserialize_long(stream: BufferedReader) -> int:
    return int.from_bytes(stream.read(8), 'big')


def deserialize_byte(stream: BufferedReader) -> int:
    return int.from_bytes(stream.read(1), 'big')


def deserialize_list(
        deserializer: Callable[[BufferedReader], T],
        stream: BufferedReader,
) -> List[T]:
    n_items = deserialize_long(stream)
    items = []
    for _ in range(n_items):
        items.append(deserializer(stream))

    return items


def serialize_bytes(stream: BufferedWriter, value: bytes) -> None:
    serialize_long(stream, len(value))
    stream.write(value)


def serialize_str(stream: BufferedWriter, value: str) -> None:
    serialize_bytes(stream, value.encode('utf-8'))


def serialize_long(stream: BufferedWriter, value: int) -> None:
    stream.write(value.to_bytes(8, 'big'))


def serialize_byte(stream: BufferedWriter, value: int) -> None:
    stream.write(value.to_bytes(1, 'big'))


def serialize_list(
        serializer: Callable[[BufferedWriter, T], None],
        stream: BufferedWriter,
        value: List[T]
) -> None:
    serialize_long(stream, len(value))
    for item in value:
        serializer(stream, item)
