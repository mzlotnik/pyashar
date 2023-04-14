# pyashar - A Tiny Python Web Server


pyashar is a tiny web server library written in Python. It is intended to be used
as a helper for other web applications. It tries to be as simple as possible
as way of keeping the code readable and maintainable. The intended result is
a secure and reliable web server.

It is compliant with currently the most stable and widely used protocol: HTTP/1.1.
Compliance does not mean that all features are implemented. It means that it implements at least the required
specification (MUST) and some common optional features (SHOULD). As such is not a full featured web server. 

As a guideline, pyashar uses the following Standards (STD):

STD 66 - RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax

STD 97 - RFC 9110 - HTTP Semaantics

STD 98 - RFC 9111 - HTTP Caching

STD 99 - RFC 9112 - HTTP/1.1


## Implementation details

It is a single file library that uses only the standard library as way of facilitating deployment and auditing. Simplicity is a priority and a strategy for keeping it secure and reliable.

As a "single threaded" server it uses asyncio to handle multiple connections. However it is not a true single threaded library as the python asyncio library uses threads to handle the tasks.

## Security

OpenBSD is a great source of inspiration for this project. For this reason, pyashar tries to follow the same security principles and practices.

### Privelege separation

pyshar drops all priveleges after opening the listening socket. All the functions