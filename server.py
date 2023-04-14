# Refactor of server.py

import asyncio
import json
import logging
import re
import traceback
from functools import partial
from typing import Tuple
from urllib.parse import urlparse, parse_qs
import mimetypes

CONTENT_LENGTH_MAX = 2**20  # 1 MB
CONTENT_TYPE_ALLOWED = {b'text/html', b'application/json', b'x-www-form-urlencoded'}

# Timeout in seconds
HTTP_REQUEST_TIMEOUT = 30.0
HTTP_RESPONSE_TIMEOUT = 60.0
HTTP_CONNECTION_TIMEOUT = 180.0

# HTTP methods
HTTP_METHODS_MUST = {b'GET', b'HEAD'}
HTTP_METHODS_OPTIONAL = {b'POST', b'PUT', b'DELETE', b'PATCH', b'CONNECT', b'OPTIONS', b'TRACE'}
HTTP_METHODS_ALLOWED = HTTP_METHODS_MUST | HTTP_METHODS_OPTIONAL
HTTP_METHOD_SAFE = HTTP_METHODS_MUST | {b'OPTIONS', b'TRACE'}
HTTP_METHODS_IMPLEMENTED = HTTP_METHODS_ALLOWED - {b'CONNECT', b'OPTIONS', b'TRACE'}


logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)


async def connection_handler(reader, writer, routes, special_routes):
    logging.info(f'New connection with {writer.get_extra_info("peername")}')
    try:
        async with asyncio.timeout(HTTP_CONNECTION_TIMEOUT) as conn_timeout:
            keep_conn = True
            while keep_conn:
                keep_conn = await request_handler(reader, writer, routes, special_routes)
                if keep_conn:
                    logging.debug('Keeping connection open')
                    new_when_to_timeout = asyncio.get_running_loop().time() + HTTP_CONNECTION_TIMEOUT
                    conn_timeout.reschedule(new_when_to_timeout)
            else:
                logging.info('Connection closed by the server')
                writer.close()

    except asyncio.TimeoutError:
        logging.info('Connection timed out')
        writer.close()

    except asyncio.IncompleteReadError:
        logging.info('Connection closed by the client')
        writer.close()


async def request_handler(reader, writer, routes, special_routes):
    try:
        asyncio.timeout(HTTP_REQUEST_TIMEOUT)
        start_line = await reader.readuntil(b'\r\n')
        start_line = start_line[:-2]  # remove the CRLF
        if len(start_line_split := start_line.split(b' ')) == 3:
            method, request_target, http_version = start_line_split
            logging.debug(f'method: {method}; request_target: {request_target}; http_version: {http_version}')
        else:
            logging.error(f'Invalid start line: {start_line}')
            raise HTTPError(400, 'Invalid start line')

        if not re.fullmatch(br'HTTP/\d(\.\d)?', http_version):
            raise BadRequest(f'Invalid http version: {http_version}')
        if http_version not in {b'HTTP/1.0', b'HTTP/1.1', b'HTTP/1'}:
            raise BadRequest(f'Http version not allowed: {http_version}')

        if not re.fullmatch(br'[\w!#$%&\'*+.^_`|~-]+', method):
            raise BadRequest(f'Invalid method: {method}')
        if method not in HTTP_METHODS_IMPLEMENTED:
            raise NotImplemented(f'Method {method} not implemented')

        if not re.fullmatch(br'^/[\w/]*\??[\w=&]*$', request_target):
            raise BadRequest(f'Invalid request target: {request_target}')

        # try early to get router function to respond with 404 to avoid reading the header fields
        origin_form = urlparse(request_target)
        path = origin_form.path.decode('utf-8')
        try:
            route_func = router(routes, path)
        except ValueError:
            logging.error(f'Route {path} not found')
            raise HTTPError(404, 'Not Found')

        header_fields = {}
        header_fields_raw = await reader.readuntil(b'\r\n\r\n')
        for field_line_raw in header_fields_raw.split(b'\r\n'):
            if field_line_raw == b'':  # end of header fields
                break
            field_name, field_value = parse_field_line(field_line_raw)
            if field_name not in header_fields:
                header_fields[field_name] = field_value
            else:
                raise BadRequest(f'Duplicate header field: {field_name}')
            logging.debug(f'Field name: {field_name}; Field value: {field_value}')

        # Validate Host
        if header_fields.get('host') is None:
            raise BadRequest('Host in the header field is required')

        # Validate Content-Length
        try:
            content_length = int(header_fields['content-length'])
            """
            A client SHOULD NOT generate content in a GET request unless it is made
            directly to an origin server that has previously indicated, in or out of
            band, that such a request has a purpose and will be adequately supported.
            """
            if method in HTTP_METHOD_SAFE:
                raise BadRequest(f'Method {method} must not have a content length')
            if content_length > CONTENT_LENGTH_MAX:
                raise BadRequest(f'Content length {content_length} exceeds the maximum allowed {CONTENT_LENGTH_MAX}')
        except KeyError:
            if method not in HTTP_METHOD_SAFE:
                raise LengthRequired('Content length required')
        except ValueError:
            raise BadRequest(f'Invalid content length: {header_fields.get("content-length")}')
        except Exception as e:
            logging.error(f'Exception: {e}')
            raise BadRequest(f'Invalid content length: {header_fields}')


        # Validate Expect
        if header_fields.get('expect') == '100-continue':
            writer.write(b'HTTP/1.1 100 Continue\r\n\r\n')
            await writer.drain()

        # Validate Connection
        match header_fields.get('connection', '').casefold():
            case 'close':
                keep_conn = False
            case 'keep-alive':
                keep_conn = True
            case _:
                keep_conn = True  # http_version == b'HTTP/1.1' if 1.0 was supported

        # Spec allows to ignore expect 100-continue

        # Content-Length body
        if header_fields.get('content-length'):
            body = await reader.readexactly(content_length)

        # read chunked body
        if 'chunked' in header_fields.get('transfer-encoding', ''):
            body = b''
            while True:
                chunk_size = await reader.readuntil(b'\r\n')
                try:
                    # get chunk size but ignore chunk extensions
                    chunk_size = chunk_size[:-2]
                    chunk_size = chunk_size.lpartition(b' ')[0]
                    chunk_size = int(chunk_size, 16)
                except ValueError:
                    raise BadRequest(f'Invalid chunk size: {chunk_size}')
                if chunk_size == 0:
                    # read and ignore trailer if any
                    trailer = await reader.readuntil(b'\r\n')
                    if trailer != b'\r\n':
                        await reader.readuntil(b'\r\n\r\n')
                    break
                body += await reader.readexactly(chunk_size)
                await reader.readuntil(b'\r\n')

            # parse body
            match header_fields.get('content-type', ''):
                case 'application/x-www-form-urlencoded':
                    body = parse_qs(body.decode())
                case 'application/json':
                    body = json.loads(body.decode())
                case _:
                    raise BadRequest(f'Can not parse content type: {header_fields.get("content-type")}')

        response = await route_func()

        # check if response is a string or a dict
        match response:
            case str():
                response = response.encode()
                r_content_type = b'Content-Type: text/html; charset=utf-8\r\n'
            case dict():
                response = json.dumps(response).encode()
                r_content_type = b'Content-Type: application/json; charset=utf-8\r\n'
            # is a file like object
            case io.IOBase():
                response = response.read()
                # check mime type using mimetypes
                guess_type = mimetypes.read_mime_types()


            case _:
                raise TypeError(f'Invalid response type: {type(response)}')

        writer.write(b'HTTP/1.1 200 OK\r\n')
        writer.write(r_content_type)
        writer.write(b'Connection: keep-alive\r\n')
        r_content_length = len(response)
        writer.write(f'Content-Length: {r_content_length}\r\n'.encode())
        writer.write(b'\r\n')
        writer.write(response)
        await writer.drain()
        return True

    except asyncio.IncompleteReadError:
        logging.warning('Connection closed by the client')
        return False
    except asyncio.TimeoutError:
        logging.error('Request timed out')
        writer.write(b'HTTP/1.1 408 Request Timeout\r\n')
        return False
    except BadRequest as exception:
        logging.error(f'Bad Request: {exception.reason_phrase}')
        writer.write(b'HTTP/1.1 400 Bad Request\r\n')
        return False
    except NotImplemented as exception:
        logging.error(f'Not Implemented: {exception.reason_phrase}')
        writer.write(b'HTTP/1.1 501 Not Implemented\r\n')
        return False
    except LengthRequired as exception:
        logging.error(f'Length Required: {exception.reason_phrase}')
        writer.write(b'HTTP/1.1 411 Length Required\r\n')
        return False
    except HTTPError as exception:
        match str(exception.status_code)[0]:
            case '4':
                logging.error(f'Client Error: {exception.status_code} {exception.reason_phrase}')
                writer.write(f'HTTP/1.1 {exception.status_code} {exception.reason_phrase}\r\n'.encode())
            case '5':
                logging.error(f'Server Error: {exception.status_code} {exception.reason_phrase}')
                writer.write(f'HTTP/1.1 {exception.status_code} {exception.reason_phrase}\r\n'.encode())
            case _:
                logging.error(f'Internal Server Error: {exception.status_code} '
                              f'is not a server or client HTTP error status code')
                writer.write(b'HTTP/1.1 500 Internal Server Error\r\n')
        writer.write(b'Connection: close\r\n')
        if special_routes.get(exception.status_code):
            response = await special_routes.get(exception.status_code)()
            writer.write(b'Content-Type: text/html; charset=utf-8\r\n')
            r_content_length = len(response)
            writer.write(f'Content-Length: {r_content_length}\r\n'.encode())
            writer.write(b'\r\n')
            writer.write(response.encode())
            await writer.drain()
        return False
    except Exception as exception:
        logging.error(f'Internal Server Error: {exception}')
        logging.error(f'Details: {traceback.format_exc()}')
        writer.write(b'HTTP/1.1 500 Internal Server Error\r\n')
        return False


async def start_server(routes: dict):
    if routes is None:
        raise ValueError("Routes is required")

    # 404 is the only default route to handle not found
    default_routes = {404: default_not_found}
    routes = default_routes | routes
    special_routes = {status_code: func for status_code, func in routes.items() if type(status_code) is int}
    logging.debug(f'Special Routes: {special_routes}')
    routes = {route_dsl_to_regex(path): func for path, func in routes.items() if type(path) is str}
    logging.debug(f'Routes: {routes}')
    partial_connection_handler = partial(connection_handler, routes=routes, special_routes=special_routes)

    # noinspection PyTypeChecker
    server = await asyncio.start_server(
        client_connected_cb=partial_connection_handler,
        host="127.0.0.1",
        port=1818,
        start_serving=False,
        limit= 64 * 1024,  # 64 KiB
    )
    await server.serve_forever()

"""
HELPER FUNCTIONS
"""


def parse_field_line(field_line_raw: bytes) -> Tuple[str, str]:
    HEADER_FIELDS_TCHAR = br'\x21-\x7E'
    try:
        field_line_raw = field_line_raw.strip()
        field_name, field_value = re.match(br'([' + HEADER_FIELDS_TCHAR + br']+)[:](.*)', field_line_raw).groups()
        field_name = field_name.decode().casefold()
        field_value = field_value.decode().strip()

    except ValueError:
        raise BadRequest(f'Invalid field line: {field_line_raw}')
    except AttributeError:
        raise BadRequest(f'Invalid field line: {field_line_raw}')

    return field_name, field_value


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
    raise ValueError(f"Route {path} not found")


async def default_not_found():
    return '<h1>Not found</h1>'


async def default_main_page():
    return '<h1>Main Page</h1>Emoji: 🌐<br>\r\n\r\n<p>new line test</p>\r\n'


"""
EXCEPTIONS
"""


class LengthRequired(Exception): # 411
    def __init__(self, reason_phrase):
        self.reason_phrase = reason_phrase


class BadRequest(Exception):
    def __init__(self, reason_phrase):
        self.reason_phrase = reason_phrase

class NotImplemented(Exception):
    def __init__(self, reason_phrase):
        self.reason_phrase = reason_phrase


class HTTPError(Exception):
    def __init__(self, status_code, reason_phrase):
        self.status_code = status_code
        self.reason_phrase = reason_phrase


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
