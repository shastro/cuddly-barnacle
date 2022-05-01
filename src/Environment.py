# Class for storing global application environment database

import os
from builtins import hasattr
from pathlib import PurePath
from typing import Any
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
import toml

from EncryptedStream import PrivateKey


class Env:
    """Singleton class to capture global program environment.

    Stores information related to the environment the application runs
    in.

    """

    def __new__(cls):
        if not hasattr(cls, "instance"):
            cls.instance = super(Env, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        homedir = os.getenv("HOME")
        self.subdir = ".chatchat"
        if homedir:
            self._root = homedir
            self._application_root = PurePath(homedir, self.subdir)
            self._configfile = PurePath(self._application_root, "config")
            self._dbfolder = PurePath(self._application_root, "database")
            self._database = PurePath(self._dbfolder, "client.db")

        if not os.path.exists(self._application_root):
            os.mkdir(self._application_root)

        if not os.path.exists(self._dbfolder):
            os.mkdir(self._dbfolder)

        self._config = Config.load_or_generate(self._configfile)

    def get_root_path(self):
        return self._root

    def get_database_path(self):
        return self._database

    def get_application_root(self):
        return self._application_root

    def get_config(self):
        return self._config


class Config:
    """Configuration data."""

    def __init__(
            self,
            networking: Any,
            security: Any,
    ) -> None:
        self.networking = NetworkingConfig(**networking)
        self.security = SecurityConfig(**security)

    @staticmethod
    def default() -> Any:
        return {
            'networking': {
                'local_addr': '0.0.0.0',
                'local_port': 18457,
            },
            'security': {
                'private_key': PrivateKey.generate().private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption(),
                ).hex(),
            },
        }

    @staticmethod
    def load_or_generate(path: str) -> 'Config':
        if os.path.exists(path):
            return Config(**toml.load(path))
        else:
            print(f'Configuration file {path} not found, creating it.')
            cfg = Config.default()
            with open(path, 'w') as cfgfile:
                cfgfile.write(toml.dumps(cfg))

            return Config(**cfg)


class NetworkingConfig:
    """Networking portion of the configuration file."""

    def __init__(
            self,
            local_addr: str,
            local_port: int,
    ) -> None:
        self.local_addr = local_addr
        self.local_port = local_port


class SecurityConfig:
    """Security portion of the configuration file."""

    def __init__(
            self,
            private_key: str,
    ) -> None:
        self.private_key = PrivateKey.from_private_bytes(
            bytes.fromhex(private_key)
        )


def tests():
    env = Env()
    print(env.get_root_path())
    print(env.get_application_root())
    print(env.get_database_path())
    print(env.get_config().networking.local_addr)


if __name__ == "__main__":
    tests()
