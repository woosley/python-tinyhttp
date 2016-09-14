import pytest
from tinyhttp import TinyHTTP

@pytest.fixture
def http():
    client = TinyHTTP(dict(timeout=2))
    return client

def test_timeout(http, httpbin):
    try:
        http.get(httpbin.url + "/delay/10")
    except Exception as e:
        assert "Timed out while waiting socket to become ready for reading" == str(e)
