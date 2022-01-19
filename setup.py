from setuptools import setup
from json import load

def convert(_input):
    if isinstance(_input, dict):
        return {convert(k): convert(v) for k, v in _input.items()}
    elif isinstance(_input, list):
        return [convert(element) for element in _input]
    elif isinstance(_input, bytes):
        return _input.decode()
    else:
        return _input

with open("package.json") as config_file:
    config = load(config_file, object_hook=convert)
    config.pop("version_hash")
    setup(**config)