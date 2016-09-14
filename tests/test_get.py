import pytest_httpbin

def test_get_base(http, httpbin):
    res = http.get(httpbin.url + "/get")
    assert res['status'] == '200'

def test_get_with_params(http, httpbin):
    res = http.get(httpbin.url + "/get?params=1&params=2")
    assert res['status'] == '200'

def test_streamed_data(http, httpbin):
    res = http.get(httpbin.url + "/stream/10")
    assert res['status'] == '200'
