import re
import errno
import select
import socket
from functools import partial

class TinyHandler(object):

    rfc_request_headers = ['Accept', 'Accept-Charset', 'Accept-Encoding',
                           'Accept-Language', 'Authorization', 'Cache-Control',
                           'Connection', 'Content-Length', 'Expect', 'From',
                           'Host', 'If-Match', 'If-Modified-Since',
                           'If-None-Match', 'If-Range', 'If-Unmodified-Since',
                           'Max-Forwards', 'Pragma', 'Proxy-Authorization',
                           'Range', 'Referer', 'TE', 'Trailer',
                           'Transfer-Encoding', 'Upgrade', 'User-Agent', 'Via']


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
        self.rbuf = ""
        self.max_header_lines = 100
        self.bufsize = 33328
        self._ist = {}

    def read(self, length, allow_partial=False):
        """ read from socket

        This function read length bites from socket, if there are already
        buffered data, read from buffer first.

        :param length:  the length of data to read
        :param allow_partial: allow partial read or not, raise Exception when
                              False and data read is less than length

        :return: data from read buffer and socket
        """
        buf = ""
        # use read buffer to cache extra stuff for readline
        got = len(self.rbuf)

        if got:
            # if there is enough data, to take is length, else take all
            to_take = length if got > length else got
            length -= to_take
            buf = self.rbuf[:to_take]
            self.rbuf = self.rbuf[to_take:]

        while length > 0:
            if self.can_read():
                raise Exception(("Timed out while waiting socket to become "
                                 "ready for reading"))
            # just raise any error
            chunk = self._ist["fh"].recv(length)

            # "quote"
            # A protocol like HTTP uses a socket for only one transfer. The
            # client sends a request, then reads a reply. That's it. The socket
            # is discarded. This means that a client can detect the end of the
            # reply by receiving 0 bytes.
            if chunk == '':
                break
            buf += chunk
            length -= len(chunk)

        if length and not allow_partial:
            raise Exception("Unexpected end of stream")

        return buf


    def readline(self):
        newlinere = r"\A([^\x0D\x0A]*\x0D?\x0A)"
        while True:
            g = re.search(newlinewre, self.rbuf)
            if g is not None:
                self.rbuf = re.sub(newlinere, "", self.rbuf)
                return g.group(1)

    def read_response_header(self):
        line = self.readline()

        regexp = re.compile(
            r"""\A(HTTP\/(0\d+\.0*))        # HTTP/1.1
                [\x09\x20+ ([0-9]{3})       # 200
                [\x09\x20]+ ([^\x0D\x0A]]*) # OK
                \x0D?\x0A]                  # \r\n """)

        g = re.search(regexp, line)
        if g is None:
            raise RuntimeError("Malformed Status-Line: {}\n".format(line))
        protocol, version, status, reason = g.groups()

        if re.search(r"0*1\.0*[01]", protocol) is None:
            raise Exception("Unsupported HTTP protocol: {}".format(protocol))

        return {
            "status": status,
            "reason": reason,
            "headers": self.read_header_lines(),
            "protocol": protocol,
        }

    def read_header_lines(self, headers=None):
        headers = headers or {}
        # regexp for header line
        headerre = re.compile(r"\A([^\x00-\x1F\x7F:]):[\x09\x20]*([^\x0D\x0A]*)")
        continuere = re.compile(r"\A[\x09\x20]+([^\x0D\x0A])*")
        count = 0
        pre_field = ""
        while True:
            count += 1
            if count > self.max_header_lines:
                raise Exception("Header lines exceedes maximum number allowed")
            line = self.readline()
            g = re.search(headerre, line)
            if g is not None:
                field_name = g.group(1).lower()
                #TODO: checkhere
                var = g.group(2)
                if field_name in headers:
                    headers[field_name].append(var)
                else:
                    headers[field_name] = [var]
                pre_field = field_name
                continue
            g = re.search(continuere, line)
            if g is not None:
                # this is a continue line
                if not pre_field:
                    raise Exception("Unexpected header continue line")
                if not len(g.group(1)): continue
                if len(headers[pre_field][-1]):
                    headers[pre_field][-1] += " "
                # append this line to the end of last header value
                headers[pre_field][-1] += g.group(1)
                continue
            if re.search(r"\A\x0D?\x0A\z", line) is not None:
                break
            raise Exception("Malformed header line: {}".format(line))
        return headers

    def read_body(self, response):
        te = response['headers'].get("transfer-encoding", "")
        chunked = filter(lambda x: "chunked" in x.lower(), te if isinstance(list, te) else [te])
        if chunked:
            return self.read_chunked_body(response)
        return self.read_content_body(response)

    def read_chunked_body(self, response):
        """ read chunked body """
        # https://en.wikipedia.org/wiki/Chunked_transfer_encoding
        lengthre = re.compile(r"\A[A-Fa-f0-9]+")
        while True:
            head = self.readline()
            g = re.search(lengthre, head)
            if g is not None:
                length = int(g.group(1), 16)
            else:
                raise Exception("Malformed chunk head: {}".format(head))
            if length == 0:
                break
            self.read_content_body(response, length)
            if self.read(2) != self.rn:
                raise Exception("Malformed chunk: missing CRLF")
        #TODO: here?
        self.read_header_lines(response['headers'])

    def read_content_body(self, response, length=None):
        length = length or response['headers'].get('content-length', 0)
        if length:
            left = length
            while left > 0:
                to_read = left if left < self.bufsize else self.bufsize
                self.read(to_read)
                left -= to_read


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

    def can_read(self):
        self.do_timeout("read", self.timeout)

    def do_timeout(self, mode, timeout):
        """ simple timeout using select."""

        fd_set = [self._ist['fh']]
        found = select.select(
            fd_set, [], [], timeout) if mode == 'read' else select.select(
                [], fd_set, [], timeout)
        return found

    def get_header_name(self, header):
        return self.headers_cased.get(header)

    def write_request(self, request):
        self.write_request_header(request['method'], request['uri'],
                                  request['headers'])
        if request['content']: self.write_request_body()

    def write_request_header(self, method, uri, headers):
        buf = "{} {} HTTP/1.1{}".format(method.upper(), uri, self.rn)
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

        response = handler.read_response_header()
        body = handler.read_body(response)
        response["body"] = body
        return response


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

