# Class for storing global application environment database

import os


class Env:
    def __init__(self, subdir: os.PathLike):
        homedir = os.getenv("HOME")
        if homedir:
            self.root = homedir
