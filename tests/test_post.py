def test_post(http, httpbin):
    res = http.post(httpbin.url + "/post", {'content': "test for fun"})
    assert res['status'] == '200'
