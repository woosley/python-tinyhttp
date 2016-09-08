def test_spliturl(http):
    url1 = "http://www.google.com/query=testquery"
    assert ('http', "www.google.com", 80, "/query=testquery", "") == http.split_url(url1)
    url2 = "https://www.google.com/"
    assert "/" == http.split_url(url2)[3]
    url3 = "https://user:pass@www.google.com/"
    assert "user:pass" == http.split_url(url3)[-1]

    url4 = "https://user%20:pass@www.google.com"
    assert "user@:pass" == http.split_url(url4)[-1]
