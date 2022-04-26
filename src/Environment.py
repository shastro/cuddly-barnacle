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
        self.subdir = ".chatchat"
        if homedir:
            self._root = homedir
            self._application_root = PurePath(homedir, self.subdir)
            self._dbfolder = PurePath(self._application_root, "database")
            self._database = PurePath(self._dbfolder, "client.db")

        if not os.path.exists(self._application_root):
            os.mkdir(self._application_root)

        if not os.path.exists(self._dbfolder):
            os.mkdir(self._dbfolder)

    def get_root_path(self):
        return self._root

    def get_database_path(self):
        return self._database

    def get_application_root(self):
        return self._application_root


def tests():
    env = Env()
    print(env.get_root_path())
    print(env.get_application_root())
    print(env.get_database_path())


if __name__ == "__main__":
    tests()
