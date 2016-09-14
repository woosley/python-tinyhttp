def test_delete(http, httpbin):
    res = http.delete(httpbin.url + "/delete", {'content': "test for fun"})
    assert res['status'] == '200'
