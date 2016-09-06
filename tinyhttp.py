import errno
import select
import socket
from functools import partial

class TinyHTTP(object):

    attributes = ('cookie_jar', 'default_headers', 'http_proxy', 'https_proxy',
                  'keep_alive', 'local_address', 'max_redirect', 'max_size',
                  'proxy', 'no_proxy', 'ssl_options', 'verify_ssl')

    rfc_request_headers = """Accept Accept-Charset Accept-Encoding
    Accept-Language Authorization Cache-Control Connection Content-Length Expect
    From Host If-Match If-Modified-Since If-None-Match If-Range
    If-Unmodified-Since Max-Forwards Pragma Proxy-Authorization Range Referer TE
    Trailer Transfer-Encoding Upgrade User-Agent Via""".split()

    other_request_headers = """Content-Encoding Content-MD5 Content-Type Cookie
    DNT Date Origin X-XSS-Protection""".split()

    headers_cased = {h.lower(): h for h in rfc_request_headers}
    headers_cased.update({h.lower(): h for h in other_request_headers})

    _agent = 'python tinyhttp client'

    rn = '\x0D\x0A'

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
        pass

    def _request(self, method, url, args):
        scheme, host, port, path_query, auth = self.split_url(url)

        self._prepare_headers_and_cb()
        #handle_request()

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

    def start_ssl(self, host):
        pass

    def write(self, buf):
        """write buffer to socket"""
        length = len(buf)
        sent = 0
        while sent < length:
            if not self.can_write():
                raise Exception("Timed out while waitting for socket to become"
                                " ready for writting\n")
            try:
                just_sent = self._ist['fh'].send(buf[sent:])
                if just_sent == 0:
                    raise RuntimeError("socket connection broken")
                sent += just_sent
            except socket.error as e:
                if isinstance(e.args, tuple):
                    if e[0] == errno.EPIPE:
                        raise RuntimeError("Socket closed by remote server")
                else:
                    raise
            except Exception:
                raise
        return sent

    def can_write(self):
        self.do_timeout("write", self.timeout)

    def do_timeout(self, mode, timeout):
        """ simple timeout using select."""

        fd_set = [self._ist['fh']]
        found = select.select(
            fd_set, [], [], timeout
        ) if mode == 'read' else select.select(
            [], fd_set, [], timeout)
        return found

    def get_header_name(self, header):
        return self.headers_cased.get(header)

    def write_request_heder(self, method, uri, headers):
        buf = ""
        seen = {}
        for i in ['host', 'cache-control', 'expect', 'max-forwards',
                  'pragma', 'range', 'te']:
            if i not in headers:
                next
            seen[i] = True
            field_name = self.get_header_name(i)
            field = headers[i]
            if not isinstance(field, list):
                field = [field]
            for f in field:
                f = f if f is not None else ""
                buf = "{}{}: {}{}".format(buf, field_name, f, self.rn)

        for k, v in headers:
            field_name = k.lower()
            if seen[field_name]: next
            field_name = self.headers_cased.get(field_name, field_name)

            field = field if isinstance(field, list) else [field]
            for i in field:
                f = f if f is not None else ""
                buf = "{}{}: {}{}".format(buf, field_name, f, self.rn)
        buf += self.rn
        return self.write(buf)

    def write_request_body(self):
        pass

    def _setup_methods(self):
        for i in ['get', 'head', 'put', 'post', 'delete']:
            setattr(self, i, partial(self.request, i))

    def set_proxies(self):
        pass

    def _validate_cookie_jar(self, cookie_jar):
        pass
