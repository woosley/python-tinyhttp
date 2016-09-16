import pytest
from tinyhttp import TinyHTTP

@pytest.fixture
def user():
    return "user"


@pytest.fixture
def passwd():
    return "pass"


@pytest.fixture
def http():
    return TinyHTTP()

def test_auth(user, passwd, http, httpbin):
    url = httpbin.url + '/basic-auth/{}/{}'.format(user, passwd)
    url = url.replace("http://", "http://{}:{}@".format(user, passwd))
    res = http.get(httpbin.url)
    assert res['status'] == '200'
