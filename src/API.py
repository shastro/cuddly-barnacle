"""External API for controlling the node."""

from flask import Flask, request, render_template, url_for
import json
from typing import Optional
from EncryptedStream import (
    PublicKey,
    PublicFormat,
)

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    # body = request.values.get('Body', None)
    # text = request.form['From']
    return render_template('index.html')


@app.route('/messages', methods=['GET'])
def messages():
    """Retrieves a list of messages falling within a time range."""
    data = MessagesReqBody(**request.args)
    print(data)

    # TODO: do something with data


@app.route('/post', methods=['POST'])
def post():
    """Posts a message to the channel."""
    data = PostReqBody(**json.loads(request.data))
    print(data)

    # TODO: do something with data


@app.route('/invite', methods=['POST'])
def invite():
    """Invites a new user to the channel."""
    data = InviteReqBody(**json.loads(request.data))
    print(data)

    # TODO: do something with data


@app.route('/ban', methods=['POST'])
def ban():
    """Removes a user from the channel."""
    data = BanReqBody(**json.loads(request.data))
    print(data)

    # TODO: do something with data


@app.route('/enter', methods=['POST'])
def enter():
    """Indicates to other users that you are online."""
    # no associated data
    pass

    # TODO: implement


@app.route('/leave', methods=['POST'])
def leave():
    """Indicates to other users that you are offline."""
    # no associated data
    pass

    # TODO: implement


class MessagesReqBody:
    def __init__(self, start: Optional[str] = None, end: Optional[str] = None):
        # Mypy thinks these operations could produce either None, an
        # int, or a string; but in actuality, they can't produce a
        # string. The proof is left as an exercise to the reader.
        self.start: Optional[int] = start and int(start)  # type: ignore
        self.end: Optional[int] = end and int(end)        # type: ignore


class PostReqBody:
    def __init__(self, message: str):
        self.message = message


class InviteReqBody:
    def __init__(self, name: str, pubkey: bytes):
        self.name = name
        self.pubkey = PublicKey.from_public_bytes(pubkey)


class BanReqBody:
    def __init__(self, name: str):
        self.name = name


if __name__ == '__main__':
    app.run()
