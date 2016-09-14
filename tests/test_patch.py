def test_patch(http, httpbin):
    res = http.patch(httpbin.url + "/patch", {'content': "test for fun"})
    assert res['status'] == '200'
