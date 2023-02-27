import asyncio
import string
import re
from urllib.parse import urlparse
from functools import partial
import logging
import json


logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)

CTL_CHARS = set(range(0, 32)) | set(range(127, 160))

# HEADER_FIELD_VALUE_CHARS_NOT_ALLOWED = CTL_CHARS - set([9, 32])  # tab and space are allowed
# RFC 9110 Section 5:
"""
field-value    = *field-content
  field-content  = field-vchar
                   [ 1*( SP / HTAB / field-vchar ) field-vchar ]
  field-vchar    = VCHAR / obs-text
  obs-text       = %x80-FF
    VCHAR          = %x21-7E
"""

HEADER_FIELDS_TCHAR = br'!#$%&\'\*\+\-\.\^_`\|~\d\w'
# HEADER_FIELDS_TCHAR = ''.join([string.ascii_letters, string.digits, "!#$%&'*+-.^_`|~" ])
HEADER_FIELDS_OBSTEXT = ''.join(chr(i) for i in range(0x80, 0xFF+1))
# HEADER_FIELDS_VCHAR = ''.join(chr(i) for i in range(0x21, 0x7F)) + HE

# Timeout in seconds
HTTP_REQUEST_TIMEOUT =  30
HTTP_RESPONSE_TIMEOUT =  30
HTTP_CONNECTION_TIMEOUT =  600

HTTP_METHODS_MUST = set([b'GET', b'HEAD'])
HTTP_METHODS_OPTIONAL = set([b'POST', b'PUT', b'DELETE', b'PATCH', b'CONNECT', b'OPTIONS', b'TRACE'])
HTTP_METHODS_ALLOWED = HTTP_METHODS_MUST | HTTP_METHODS_OPTIONAL
HTTP_METHOD_SAFE = HTTP_METHODS_MUST | set([b'OPTIONS', b'TRACE'])
HTTP_METHODS_IMPLEMENTED = HTTP_METHODS_ALLOWED - set([b'CONNECT', b'OPTIONS', b'TRACE'])

HTTP_VERSIONS_ALLOWED = set([b'HTTP/1.0', b'HTTP/1.1', b'HTTP/1'])

CONTENT_LENGTH_MAX =  2**20  # 1 MB

CONTENT_TYPE_ALLOWED = set([b'text/html', b'application/json'])


HEADER_FIELDS_DEFAULT = {
    'Connection': 'keep-alive',
    'Content-Type': 'text/html',
    'Content-Length': '0',
    'Server': 'pyni',
    'Date': 'Tue, 16 Jun 2020 13:13:00 GMT'
}

HEADER_FIELDS_DEFAULT_SECURITY = {
    'Content-Security-Policy': 'default-src \'self\'',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block'
}

def route_dsl_to_regex(dsl: str) -> str:
    pattern = r'(<\w+>)'  # match the parameter
    replacement = r'(?P\1[^/]+)'  # replace with a named capture group
    return re.sub(pattern, replacement, dsl)


def router(routes, path):
    for pattern, func in routes.items():
        match = re.fullmatch(pattern, path)
        if match:
            kwargs = match.groupdict()
            return partial(func, **kwargs)
    logging.error(f"Route {path} not found")
    raise ValueError(f"Route {path} not found")


# it must also comply with http 1.1 by using as reference the RFCs 3986, 9110, 9111 and 9112.
async def request_handler(reader, writer, routes, special_routes):

    async def bad_request(log_message):
        """
        The 400 (Bad Request) status code indicates that the server cannot or will not
        process the request due to something that is perceived to be a client error
        (e.g., malformed request syntax, invalid request message framing, or deceptive
        equest routing).
        """
        logging.error(log_message)
        await response_single_line(writer, 400, 'Bad Request', [])
        writer.close()

    logging.info('Request Received')
    # HTTP-message = start-line CRLF
    #              *( field-line CRLF )
    #              CRLF
    #              [ message-body ]
    #
    # request-line = method SP request-target SP HTTP-version
    try:
        start_line = await reader.readuntil(b'\r\n')
    except asyncio.IncompleteReadError:
        logging.error('IncompleteReadError')
        writer.close()
    except asyncio.LimitOverrunError:
        logging.error('LimitOverrunError')
        writer.close()
    except asyncio.TimeoutError:
        logging.error('TimeoutError')
        writer.close()

    start_line = start_line[:-2]  #  remove the CRLF
    if len(start_line_split := start_line.split(b' ')) == 3:
        method, request_target, http_version = start_line_split
        logging.debug(f'method: {method}; request_target: {request_target}; http_version: {http_version}')
    else:
        await bad_request(f'Invalid request line: {start_line}')
        return 0
    
    # HTTP-version = HTTP-name "/" DIGIT "." DIGIT
    # HTTP-name = %s"HTTP"
    # RFC 9110 Section 2.5:
    # When a major version of HTTP does not define any minor versions, the minor version "0" is implied.
    # regex must support bytes
    if not re.fullmatch(br'HTTP/\d(\.\d)?', http_version):
        await bad_request(f'Invalid http version: {http_version}')
        return 0
    if http_version not in HTTP_VERSIONS_ALLOWED:
        logging.error(f'Http version not allowed: {http_version}')
        await response_single_line(writer, 505, 'HTTP Version Not Supported', [])
        return 0

    # method = token
    # token = 1*tchar
    # tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    # check if method follows the token syntax
    if not re.fullmatch(br'[\w!#$%&\'*+.^_`|~-]+', method):
        bad_request(f'Invalid method: {method}')
        return 0
    if method not in HTTP_METHODS_IMPLEMENTED:
        logging.error(f'Method {method} not implemented')
        await response_single_line(writer, 501, 'Not Implemented', [])
        return 0

    # request-target = origin-form
    #                / absolute-form
    #                / authority-form
    #                / asterisk-form
    # only origin-form is implemented
    # origin-form = absolute-path [ "?" query ]
    # absolute-path example: /index.html, /path/to/file
    # query example: ?key=value&key2=value2
    if not re.fullmatch(br'^/[\w/]*\??[\w=&]*$', request_target):
        await bad_request(f'Invalid request target: {request_target}')
        return 0
    
    # try early to get router function to respond with 404 before reading the header fields
    origin_form = urlparse(request_target)
    path = origin_form.path.decode('utf-8')
    try:
        route_func = router(routes, path)
    except ValueError:
        logging.error(f'Route {path} not found')
        await response_single_line(writer, 404, 'Not Found', [])
        return 0

    header_fields = {}
    # field-line = field-name ":" OWS field-value OWS
    """
    # Other way to read the header fields:
    for field_line in await reader.readuntil(b'\r\n'):
        # If CRLF it is end of the header fields
        if field_line == b'\r\n':
            break
    """
    # bulk reading the header fields to avoid non-blocking overhead
    header_fields_raw = await reader.readuntil(b'\r\n\r\n')
    for field_line in header_fields_raw.split(b'\r\n'):
        # If CRLF it is end of the header fields
        if field_line == b'':
            break
        try:
            field_line = field_line.strip() # remove OWS (optional whitespace)
            # field name must not contain OWS before colon
            # regex match by HEADER_FIELDS_TCHAR + colon. The colon is not included in the match. The result is a tuple with 2 elements:
            # the first element is the field name and the second element is the field value
            field_name, field_value = re.match(br'([' + HEADER_FIELDS_TCHAR + br']+)[:](.*)', field_line).groups()

        except ValueError:
            await bad_request(f'Invalid field line: {field_line}')
            return 0
        field_value = field_value.strip() # remove OWS (optional whitespace)
        # field name must be unique
        if field_name in header_fields:
            await bad_request(f'Duplicate field name: {field_name}')
            return 0
        # field name is case insensitive so it is converted to lower case
        header_fields[field_name.lower()] = (field_name, field_value)
        logging.debug(f'Field name: {field_name}; Field value: {field_value}')

    # message-body = *OCTET
    # message_body = await reader.readuntil(b'\r\n')
    # logging.debug(f'Message body: {message_body}')

    # get the Content-Length
    try:
        content_length = int(header_fields[b'content-length'][1])
        """
        A client SHOULD NOT generate content in a GET request unless it is made
        directly to an origin server that has previously indicated, in or out of
        band, that such a request has a purpose and will be adequately supported.
        """
        if method in HTTP_METHOD_SAFE:
            await bad_request(f'Method {method} must not have a content length')
            return 0
        if content_length > CONTENT_LENGTH_MAX:
            await bad_request(f'Content length {content_length} exceeds the maximum allowed {CONTENT_LENGTH_MAX}')
            return 0
    except KeyError:
        if method not in HTTP_METHOD_SAFE:
            await response_single_line(writer, 411, 'Length Required', [])
            return 0
    except ValueError:
        await bad_request(f'Invalid content length: {header_fields[b"Content-Length"]}')
        return 0
    
    # get the Content-Type
    try:
        content_type = header_fields[b'content-type'][1]
        if method in HTTP_METHOD_SAFE:
            await bad_request(f'Method {method} must not have a content type')
            return 0
        if content_type not in CONTENT_TYPE_ALLOWED:
            await bad_request(f'Content type {content_type} not allowed')
            return 0
    except KeyError:
        if method not in HTTP_METHOD_SAFE:
            await bad_request(f'Method {method} must have a content type')
            return 0
        
    # get the content
    if method not in HTTP_METHOD_SAFE:
        content = await reader.readexactly(content_length)
        logging.debug(f'Content: {content}')
    

    # normal request routing
    if route_func not in special_routes:
        response_body = await route_func()
        await response(writer, 200, 'OK', [('Content-Type', 'text/html')], response_body)
        return 0



async def response_single_line(writer, status_code, status_text, headers):
    writer.write(f'HTTP/1.1 {status_code} {status_text}\r\n'.encode())
    for header in headers:
        writer.write(f'{header[0]}: {header[1]}\r\n')
    writer.write(b'\r\n')
    await writer.drain()
    writer.close()

async def response(writer, status_code, status_text, headers, body):
    body = body.encode()
    writer.write(f'HTTP/1.1 {status_code} {status_text}\r\n'.encode())
    # Content-Length header field is required for HTTP/1.1
    headers.append(('Content-Length', str(len(body))))
    for header in headers:
        writer.write(f'{header[0]}: {header[1]}\r\n'.encode())
    writer.write(b'\r\n')
    writer.write(body)
    await writer.drain()
    writer.close()
    # end of request
    logging.info('Request Ended')
    return 0




async def start_server(routes=None):
    """
    Start server async loop but first parse the routes
    """
    if routes is None:
        raise ValueError("Routes is required")
    
    # 404 is the only default route to handle not found
    default_routes = {404: default_not_found}
    routes = default_routes | routes
    special_routes = {status_code: func for status_code, func in routes.items() if type(status_code) is int}
    logging.debug(f'Special Routes: {special_routes}')
    routes = {route_dsl_to_regex(path): func for path, func in routes.items() if type(path) is str}
    logging.debug(f'Routes: {routes}')
    partial_request_handler = partial(request_handler, routes=routes, special_routes=special_routes)
    
    server = await asyncio.start_server(
        client_connected_cb=partial_request_handler,
        host="127.0.0.1",
        port=1818,
        start_serving=False,
    )
    await server.serve_forever()


async def default_not_found():
    return '<h1>Not found</h1>'

async def default_main_page():
    return '<h1>Main Page</h1>Emoji: 🌐<br>\r\n\r\n<p>new line test</p>\r\n'

if __name__ == '__main__':
    # Sample application
    routes = {
        '/': default_main_page,
        '/404': default_not_found,
    }
    try:
        asyncio.run(start_server(routes=routes))
    except KeyboardInterrupt:
        logging.warning("Server Interrupted")

"""
     with open('main.html', 'r') as file:
        main_page = file.read()
    writer.writelines([
        c_h11.send(h11.Response(headers=[], status_code=200)),
        c_h11.send(h11.Data(main_page.encode())),
        c_h11.send(h11.EndOfMessage()),
    ])
"""


"""
async def request_handler(reader, writer, routes, special_routes):
    logging.info('Request Received')
    c_h11 = h11.Connection(h11.SERVER)
    data = await reader.readuntil(b'\r\n\r\n')
    request_line = data.split(b'\r\n')[0]
    if rl_split := request_line.split(b' ') and len(rl_split) == 3:
        method, url_path, http_version = rl_split
        logging.debug(f'Method: {method}; url: {url_path}; http_version: {http_version}')
    else:
        logging.error(f'Invalid request line: {request_line}')
        writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        writer.write(b'')
        await writer.drain()
        writer.close()
        return 0
    c_h11.receive_data(data)
    event = c_h11.next_event()
    url_path = urlparse(event.target).path.decode()
    logging.debug(f'url: {url_path}')
    try:
        route_func = router(routes, url_path)
        content = await route_func()
        logging.debug(type(content))
    except ValueError:
        if r404 := special_routes.get(404):
            content = await r404()
    if not content:
        logging.debug(f'No content to display')
        writer.write(b'HTTP/1.1 204 No content\r\n\r\n')
        writer.write(b'')
        await writer.drain()
        writer.close()
        return 0

    if type(content) is str:
        logging.debug(f'Html content')
        writer.writelines([
            c_h11.send(h11.Response(headers=[('Content-type', 'text/html; charset=utf-8')], status_code=200)),
            c_h11.send(h11.Data(content.encode())),
            c_h11.send(h11.EndOfMessage()),
        ])
        await writer.drain()
        writer.close()
        return 0

    elif isinstance(content, pathlib.Path):
        if not os.path.exists(content):
            raise FileNotFoundError(f"{content} does not exist.")
        content_type = str(mimetypes.guess_type(content))
        logging.debug(f'other type of content: {str(content_type)}')
        header = [
            ('Content-type', content_type[0]),
            ('Cache-Control', 'no-store'),
        ]
        with open(content, 'rb') as file:
            content_data = file.read()
            writer.writelines([
                c_h11.send(h11.Response(headers=header, status_code=200)),
                c_h11.send(h11.Data(content_data)),
                c_h11.send(h11.EndOfMessage()),
            ])
        await writer.drain()
        writer.close()
        return 0
    else:
        logging.debug(f'Json content')
        content = json.dumps(content)
        header = [
            ('Content-type', 'application/json; charset=utf-8'),
            ('Cache-Control', 'no-store'),
        ]
        writer.writelines([
            c_h11.send(h11.Response(headers=header, status_code=200)),
            c_h11.send(h11.Data(content.encode())),
            c_h11.send(h11.EndOfMessage()),
        ])
        await writer.drain()
        writer.close()
        return 0
    \"""
    writer.writelines([
        c_h11.send(h11.Response(headers=[('Content-type', 'text/html; charset=utf-8')], status_code=200)),
        c_h11.send(h11.Data(content.encode())),
        c_h11.send(h11.EndOfMessage()),
    ])
    \"""
    await writer.drain()
    writer.close()
    logging.debug(c_h11.states)
"""