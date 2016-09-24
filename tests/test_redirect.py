import pytest_httpbin

def test_redirect(http, httpbin):
    res = http.get(httpbin.url + "/redirect/3")
    assert res['status'] == '200'
    res = http.get(httpbin.url + '/absolute-redirect/3')
    assert res['status'] == '200'


def test_max_redirect(http, httpbin):
    try:
        res = http.get(httpbin.url + "/absolute-redirect/6")
    except Exception as e:
        assert(str(e) == "Max redirection exceeded")
