import pytest_httpbin

def test_get_base(http, httpbin):
    res = http.get(httpbin.url + "/get")
    assert res['status'] == '200'

