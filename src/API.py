"""External API for controlling the node."""

from flask import Flask, request, render_template, flash
import json
from typing import Optional
from EncryptedStream import PublicKey
# from Node import Node
import Event
import datetime
import Environment

app = Flask(__name__)

# Putting this at the top, despite that this'll automatically connect
# to the network immediately upon loading the library. Not sure how
# else to easily communicate state to a Flask app.
# node = Node()


@app.route('/', methods=['GET', 'POST'])
def index():
    # body = request.values.get('Body', None)
    # text = request.form['From']
    return render_template('index.html')


@app.route('/messages', methods=['GET', 'POST'])
def messages():
    """Retrieves a list of messages falling within a time range."""
    # data = MessagesReqBody(**request.args)
    data = ["Airplane food, ammmie right guys", "bro what's an airplane",
    "airplanes have food?", "my dad said he saw an airplane once",
    "oh yeah I have like 8 airplanes, get gud"]
    text = request.form
    print(text)
    # print(data)
    # return render_template('test.html', messages=data)
    return render_template('msg.html', messages=data)

    # TODO: do something with data


@app.route('/post', methods=['POST'])
def post():
    """Posts a message to the channel."""
    data = PostReqBody(**json.loads(request.data))
    print(data)

    node.handle_event(Event.Event(
        Event.EventMessagePost(
            Environment.Env().get_config().general.nickname,
            datetime.datetime.now().timestamp(),
            data.message
        )
    ))


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


@app.route('/enter', methods=['GET', 'POST'])
def enter():
    """Indicates to other users that you are online."""
    # no associated data
    text = request.form
    print(text)
    return render_template('connect.html')

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
