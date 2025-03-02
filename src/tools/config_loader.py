import os

def configJSON():
    """returns config.json path"""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "configs", "config.json")