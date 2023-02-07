import asyncio
import re
import h11
from urllib.parse import urlparse
from functools import partial
import logging
import json
import pathlib
import mimetypes
import os

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)


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


async def request_handler(reader, writer, routes, special_routes):
    logging.info('Request Received')
    c_h11 = h11.Connection(h11.SERVER)
    data = await reader.readuntil(b'\r\n\r\n')
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
    """
    writer.writelines([
        c_h11.send(h11.Response(headers=[('Content-type', 'text/html; charset=utf-8')], status_code=200)),
        c_h11.send(h11.Data(content.encode())),
        c_h11.send(h11.EndOfMessage()),
    ])
    """
    await writer.drain()
    writer.close()
    logging.debug(c_h11.states)


async def start_server(routes=None):
    default_routes = {404: default_not_found}
    if routes is None:
        raise ValueError("Routes is required")
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

if __name__ == '__main__':
    try:
        asyncio.run(start_server())
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