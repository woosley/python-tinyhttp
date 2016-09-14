def test_put(http, httpbin):
    res = http.put(httpbin.url + "/put", {'content': "test for fun"})
    assert res['status'] == '200'
