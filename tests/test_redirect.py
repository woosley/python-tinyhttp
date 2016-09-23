import pytest_httpbin

def test_redirect(http, httpbin):
    res = http.get(httpbin.url + "/redirect/2")
    assert res['status'] == '200'
    res = http.get(httpbin.url + '/absolute-redirect/2')
    assert res['status'] == '200'

