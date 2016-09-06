class tinyhttp(object):

    attributes = ('cookie_jar', 'default_headers', 'http_proxy', 'https_proxy',
                  'keep_alive', 'local_address', 'max_redirect', 'max_size',
                  'proxy', 'no_proxy', 'ssl_options', 'verify_ssl')

    _agent = 'python tinyhttp client'

    def __init__(self, args):
        self.max_redirect = 5
        self.timeout = args.get('timeout', 60)
        self.keep_alive = True
        self.verify_ssl = args.get('verify_ssl', False)
        self.agent = args.get("agent", self._agent)
        if args.get('cookie_jar'):
            self._validate_cookie_jar(args.get('cookie_jar'))

        for i in args:
            if i in args and not hasattr(self, i):
                setattr(self, i, args[i])

        self.set_proxies()

    def _request(self, method, url, args):
        pass

    def set_proxies():
        pass

    def _validate_cookie_jar(self, cookie_jar):
        pass
