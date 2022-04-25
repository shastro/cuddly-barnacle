# Class for storing global application environment database

import os
from builtins import hasattr
from pathlib import PurePath


class Env:
    """Singleton class to capture global program state.

    Stores information related to the environment the application runs
    in.

    """

    def __new__(cls):
        if not hasattr(cls, "instance"):
            cls.instance = super(Env, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        homedir = os.getenv("HOME")
        if homedir:
            self.root = homedir
            self.database = PurePath(homedir, "database", "client.db")

    def get_root_path(self):
        return self.root

    def get_database_path(self):
        return self.database


def tests():
    env = Env()
    env2 = Env()
    print(env.get_root_path())
    print(env2.get_root_path())
    print(env.get_database_path())


if __name__ == "__main__":
    tests()
