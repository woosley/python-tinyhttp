import pytest
from tinyhttp import TinyHTTP


@pytest.fixture
def http():
    h = TinyHTTP({})
    return h
