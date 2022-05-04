"""External API for controlling the node."""

from flask import Flask, request, render_template, flash
import json
from typing import Optional
from EncryptedStream import PublicKey
from Node import Node
import Event
import datetime
import Environment

app = Flask(__name__)

# Putting this at the top, despite that this'll automatically connect
# to the network immediately upon loading the library. Not sure how
# else to easily communicate state to a Flask app.
node = Node()


@app.route('/', methods=['GET', 'POST'])
def index():
    data = [
        "Airplane food, ammmie right guys",
        "bro what's an airplane",
        "airplanes have food?",
        "my dad said he saw an airplane once",
        "oh yeah I have like 8 airplanes, get gud",
    ]
    text = request.form
    print(text)
    # print(data)
    # return render_template('test.html', messages=data)
    return render_template('msg.html', messages=data)


@app.route('/connect', methods=['GET', 'POST'])
def connect_page():
    return render_template('connect.html')


@app.route('/api/messages', methods=['GET'])
def messages():
    """Retrieves a list of messages falling within a time range."""
    data = MessagesReqBody(**request.args)
    print(data)

    return '\n'.join(node.get_messages(data.start, data.end))


@app.route('/api/status', methods=['GET'])
def status():
    """Gets the current status of the node."""
    return node.get_states()


@app.route('/api/connect', methods=['POST'])
def connect():
    """Adds an address to the peer list."""
    data = ConnectReqBody(**json.loads(request.data))
    print(data)

    node.add_address(data.addr)

    return "ok"


@app.route('/api/post', methods=['POST'])
def post():
    """Posts a message to the channel."""
    data = PostReqBody(**json.loads(request.data))
    print(data)

    node.handle_event(Event.Event(
        Event.EventMessagePost(
            Environment.Env().get_config().general.nickname,
            int(datetime.datetime.now().timestamp()),
            data.message,
        )
    ))

    return "ok"


@app.route('/api/invite', methods=['POST'])
def invite():
    """Invites a new user to the channel."""
    data = InviteReqBody(**json.loads(request.data))
    print(data)

    # TODO: do something with data


@app.route('/api/ban', methods=['POST'])
def ban():
    """Removes a user from the channel."""
    data = BanReqBody(**json.loads(request.data))
    print(data)

    # TODO: do something with data


@app.route('/api/enter', methods=['GET', 'POST'])
def enter():
    """Indicates to other users that you are online."""
    # no associated data
    pass

    # TODO: implement


@app.route('/api/leave', methods=['POST'])
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


class ConnectReqBody:
    def __init__(self, addr: str, port: int):
        self.addr = (addr, port)


if __name__ == '__main__':
    app.run(port=Environment.Env().get_config().networking.api_port)
