"""External API for controlling the node."""

from flask import Flask, request, render_template, url_for
import json

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    # body = request.values.get('Body', None)
    # text = request.form['From']
    return render_template('index.html')


@app.route('/messages', methods=['GET'])
def messages():
    """Retrieves a list of messages falling within a time range."""
    pass


@app.route('/post', methods=['POST'])
def post():
    """Posts a message to the channel."""
    pass


@app.route('/invite', methods=['POST'])
def invite():
    """Invites a new user to the channel."""
    pass


@app.route('/ban', methods=['POST'])
def ban():
    """Removes a user from the channel."""
    pass


@app.route('/enter', methods=['POST'])
def enter():
    """Indicates to other users that you are online."""
    pass


@app.route('/leave', methods=['POST'])
def leave():
    """Indicates to other users that you are offline."""
    pass


if __name__ == '__main__':
    app.run()
