"""External API for controlling the node."""

from flask import Flask, request
import json

api = Flask(__name__)


@api.route('/login', methods=['POST'])
def login():
    data: LoginData = json.loads(
        request.data,
        object_hook=lambda d: LoginData(**d)
    )

    if data.is_valid():
        return {
            'success': True,
            'token': '123',
        }
    else:
        return {
            'success': False,
        }


class LoginData:
    def __init__(self, user: str, password: str) -> None:
        self.user = user
        self.password = password

    def is_valid(self) -> bool:
        return check_credentials(self.user, self.password)


class MessagePostData:
    def __init__(self, post: str) -> None:
        pass


def check_credentials(user: str, pwd: str) -> bool:
    """Temporary stub for checking login credentials."""

    return user == 'alex' and pwd == '12345'


if __name__ == '__main__':
    api.run()
