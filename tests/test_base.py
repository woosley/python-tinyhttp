def test_methods(http):
    for i in ['get', 'post', 'put', 'head']:
        assert hasattr(http, i)
