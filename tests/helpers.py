__all__ = [
    'generateId',
    'generateString',
    'generateIP',
]
import random
import string


def generateId():
    return ''.join(random.choice(string.hexdigits) for _ in range(8))


def generateString(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def generateIP():
    return '.'.join(str(random.randint(0, 255)) for _ in range(3))


def randomPort(min=None, max=None):
    min = min or 80
    max = max or 90
    return random.randint(min, max)
