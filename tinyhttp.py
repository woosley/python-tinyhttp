import re
import errno
import select
import socket
from functools import partial

class TinyHandler(object):
    rfc_request_headers = """Accept Accept-Charset Accept-Encoding
    Accept-Language Authorization Cache-Control Connection Content-Length Expect
    From Host If-Match If-Modified-Since If-None-Match If-Range
    If-Unmodified-Since Max-Forwards Pragma Proxy-Authorization Range Referer TE
    Trailer Transfer-Encoding Upgrade User-Agent Via""".split()

    other_request_headers = """Content-Encoding Content-MD5 Content-Type Cookie
    DNT Date Origin X-XSS-Protection""".split()

    # keep this to make pylint happy
    headers_cased = {}
    for h in rfc_request_headers:
        headers_cased[h.lower()] = h
    for h in other_request_headers:
        headers_cased[h.lower()] = h


    rn = '\x0D\x0A'

    def __init__(self, timeout, keep_alive):
        self.timeout = timeout
        self.keep_alive = keep_alive

    def connect(self, scheme, host, port, peer):
        if scheme == "https":
            pass
        elif scheme != "http":
            raise Exception("Unsupported URL scheme %s" % scheme)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if self.keep_alive:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.connect(host, port)

        if scheme == 'https': self.start_ssl(host)
        self._ist["fh"] = sock
        return sock

    def can_write(self):
        self.do_timeout("write", self.timeout)

    def do_timeout(self, mode, timeout):
        """ simple timeout using select."""

        fd_set = [self._ist['fh']]
        found = select.select(fd_set, [], [], timeout) if mode == 'read' else select.select([], fd_set, [], timeout)
        return found

    def get_header_name(self, header):
        return self.headers_cased.get(header)

    def write_request(self, request):
        self.write_request_header(request['method'], request['uri'],
                                  request['headers'])
        if request['content']: self.write_request_body()

    def write_request_header(self, method, uri, headers):
        buf = ""
        seen = {}
        for i in ['host', 'cache-control', 'expect', 'max-forwards',
                  'pragma', 'range', 'te']:
            if i not in headers:
                continue
            seen[i] = True
            field_name = self.get_header_name(i)
            field = headers[i]
            if not isinstance(field, list):
                field = [field]
            for f in field:
                f = f if f is not None else ""
                buf = "{}{}: {}{}".format(buf, field_name, f, self.rn)

        for k, v in headers.items():
            field_name = k.lower()
            if seen[field_name]: next
            field_name = self.headers_cased.get(field_name, field_name)

            v = v if isinstance(v, list) else [v]
            for i in field:
                f = f if f is not None else ""
                buf = "{}{}: {}{}".format(buf, field_name, f, self.rn)
        buf += self.rn
        return self.write(buf)

    def write_request_body(self, request):
        content_length = request['headers']['content_length']
        length = self.write(request['content'])
        if length != content_length:
            raise RuntimeError("Length mismatch {} != {}".format(
                length, content_length))


class TinyHTTP(object):

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

        self._setup_methods()
        self.set_proxies()

    def request(self, method, url, args={}):
        assert isinstance(args, dict)
        for _ in [0, 1]:
            res = self.request(method, url, args)
        return res

    def split_url(self, url):
        regexp = r'([^:/?#]+)://([^/?#]*)([^#]*)'
        g = re.match(regexp, url)
        if g is not None:
            scheme, host, path_query = g.groups()
        else:
            raise RuntimeError("Can not parse URL: %s" % url)

        scheme = scheme.lower()
        if not path_query.startswith("/") : path_query = "/%s" % path_query

        auth = ""
        pos = host.find("@")
        if pos != -1:
            auth = host[:pos]
            host = host[pos + 1:]
        #Todo: fix persent escape
        g = re.search(r":(\d+)$", host)
        port = None
        if g is not None:
            port = g.group(1)
            host = re.sub(r":\d+$", "", host)
        else:
            port = 443 if scheme == 'https' else 80
        return (scheme, host, port, path_query, auth)

    def _request(self, method, url, args):
        scheme, host, port, path_query, auth = self.split_url(url)
        request = {
            "method": method,
            "scheme": scheme,
            "host": host,
            "port": port,
            "host_port": "{}:{}".format(host, port),
            "uri": path_query,
            "headers": {},
        }
        self._prepare_headers(request, args, url, auth)
        handler = TinyHandler()
        handler.write_request(request)

    def _prepare_headers(self, request, args, url, auth):
        for k, v in args['headers'].items():
            request['headers'][k.lower()] = v
            request['headers_case'][k.lower()] = v

        if 'host' in request['headers']:
            raise RuntimeError("Host can not be provided as header")

        request['headers']["host"] = request['host_port']
        if not self.keep_alive: request['headers']["connection"] = 'close'
        request['headers'].setdefault('user-agent', self.agent)

        if 'content' in args:
            request['headers']['content-length'] = len(args['content'])
            request['headers']['content-type'] = 'application/octet-stream'
        #TODO: setup cookjar
        #TODO: setup basic authentication
        self._open_handler(request)

    def _setup_methods(self):
        for i in ['get', 'head', 'put', 'post', 'delete']:
            setattr(self, i, partial(self.request, i))

    def set_proxies(self):
        pass

    def _validate_cookie_jar(self, cookie_jar):
        pass

    def _open_handler(self, request, scheme, host, port, peer):
        handler = TinyHandler(timeout=self.timeout,
                              keep_alive=self.keep_alive)
        self.handler = handler
        handler.connect(scheme, host, port, peer)


if __name__ == '__main__':
    http = TinyHTTP({})

