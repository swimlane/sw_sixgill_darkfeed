from setuptools import setup
from json import load
from six import iteritems


def convert(_input):
    if isinstance(input, dict):
        return {convert(k): convert(v) for k, v in iteritems(_input)}
    elif isinstance(input, list):
        return [convert(element) for element in _input]
    elif isinstance(input, bytes):
        return input.decode()
    else:
        return input


with open("package.json") as config_file:
    config = load(config_file, object_hook=convert)
    config.pop("version_hash")
    setup(**config)
