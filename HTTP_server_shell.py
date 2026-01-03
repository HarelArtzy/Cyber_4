"""
 Program: HTTP Server Shell
 Author: Harel Teva Artzy
 Description: A http protocol server shell for an existing site template,
              handles client requests from browser and infinite clients, one after the other.
"""

import socket
import os
from email.utils import formatdate
import logging


QUEUE_SIZE = 10
IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 2

WEB_ROOT = "webroot"
DEFAULT_URL = "index.html"

STATUS_CODES = {
    "/400": {
        "status": "400 Bad Request",
        "headers": {},
        "body": True
    },
    "/404": {
        "status": "404 Not Found",
        "headers": {},
        "body": True
    },
    "/forbidden": {
        "status": "403 Forbidden",
        "headers": {},
        "body": True
    },
    "/forbidden/": {
        "status": "403 Forbidden",
        "headers": {},
        "body": True
    },
    "/moved": {
        "status": "302 Moved Temporarily",
        "headers": {"Location": "/"},
        "body": False
    },
    "/moved/": {
        "status": "302 Moved Temporarily",
        "headers": {"Location": "/"},
        "body": False
    },
    "/error": {
        "status": "500 Internal Server Error",
        "headers": {},
        "body": True
    },
    "/error/": {
        "status": "500 Internal Server Error",
        "headers": {},
        "body": True
    }
}

CONTENT_TYPES = {
    "html": "text/html;charset=utf-8",
    "jpg": "image/jpeg",
    "css": "text/css",
    "js": "text/javascript; charset=UTF-8",
    "txt": "text/plain",
    "ico": "image/x-icon",
    "gif": "image/jpeg",
    "png": "image/png"
}


def get_file_data(file_name: str):
    """
    Get data from file
    :param file_name: the name of the file
    :return: data from file in bytes, or None if error
    """
    try:
        with open(file_name, "rb") as f:
            return f.read()
    except OSError:
        logging.exception(f"Failed reading file: {file_name}")
        return None


def get_content_type(file_name: str) -> str:
    """
    Get content type
    :param file_name: the name of the file
    """
    if "." in file_name:
        ext = file_name.rsplit(".", 1)[1].lower()
    else:
        ext = ""

    return CONTENT_TYPES.get(ext, "text/plain")


def build_http_header(status_code, content_type=None, content_length=None, extra_headers=None):
    """
    Build HTTP header
    :param status_code: the HTTP status code (400/404/403...)
    :param content_type: txt, jpg, png, ...
    :param content_length: length of data in bytes
    :param extra_headers: lines that are not in every header like Location
    :return:
    """
    lines = [f"HTTP/1.1 {status_code}"]
    if content_type is not None:
        lines.append(f"Content-Type: {content_type}")
    if content_length is not None:
        lines.append(f"Content-Length: {content_length}")
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines.append("Date: " + formatdate(timeval=None, localtime=False, usegmt=True))
    http_header = "\r\n".join(lines) + "\r\n\r\n"
    return http_header


def handle_client_request(resource: str, client_socket: socket.socket) -> None:
    """
    Check the resource, generate HTTP response and send
    to client
    :param resource: The URI
    :param client_socket: Server-Client's socket
    :return: None
    """
    logging.info(f"Request resource: {resource}")

    if resource in STATUS_CODES:
        resource_dict = STATUS_CODES[resource]
        status = resource_dict["status"]
        extra_headers = resource_dict["headers"]
        has_body = resource_dict["body"]

        if has_body:
            body = b"<html><body><h1>" + status.encode() + b"</h1></body></html>"
        else:
            body = b""

        http_header = build_http_header(
            status,
            content_type="text/html;charset=utf-8",
            content_length=len(body),
            extra_headers=extra_headers
        )

        http_response = http_header.encode() + body
        logging.info(f"Responding: {status}")

    else:
        if resource == "/" or resource == "":
            relative_path = DEFAULT_URL
        else:
            relative_path = resource.lstrip("/")
            relative_path = relative_path.split("?", 1)[0]

        full_path = os.path.join(WEB_ROOT, relative_path)
        logging.info(f"Path: {full_path}")

        if not os.path.isfile(full_path):
            handle_client_request("/404", client_socket)
            return

        data = get_file_data(full_path)
        if data is None:
            handle_client_request("/error", client_socket)
            return

        content_type = get_content_type(full_path)
        logging.info(
            f"Responding 200: {full_path}, "
            f"Content-Type={content_type}, Content-Length={len(data)}"
        )

        http_header = build_http_header("200 OK",
                                        content_type=content_type,
                                        content_length=len(data))
        http_response = http_header.encode() + data
    client_socket.sendall(http_response)


def validate_http_request(request: str) -> tuple:
    """
    Check if request is a valid HTTP request and returns true or false and
    the requested URL
    :param request: The client's request
    :return: a tuple of (True/False, requested resource)
    """
    if not request:
        return False, ""

    if "\r\n\r\n" not in request:
        return False, ""

    lines = request.split("\r\n")
    request_line = lines[0]

    parts = request_line.split(" ")
    if len(parts) != 3:
        return False, ""
    method, uri, version = parts

    if method != "GET":
        return False, ""
    if version != "HTTP/1.1":
        return False, ""

    return True, uri


def handle_client(client_socket):
    """
    Verifies client's requests are legal HTTP, calls
    function to handle the requests
    :param client_socket: The Server-Client socket
    :return: None
    """
    while True:
        try:
            client_request = client_socket.recv(4096).decode()

        except socket.timeout:
            logging.info("Socket timeout")
            break

        # this may happen because of the new page that I added for 404,500, etc.
        except ConnectionAbortedError:
            logging.info("Client closed connection")
            break

        except Exception as e:
            logging.info(f"Error: {e}")
            break

        if not client_request:
            logging.info("Client closed connection")
            break

        logging.info(f"Received request ({len(client_request)} bytes)")
        print("Received request:")
        print(client_request)

        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            logging.info(f"Valid HTTP request: {resource}")
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
        else:
            handle_client_request("/400", client_socket)
            break


def main():
    """
    The main function initiating the server shell
    :return:
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((IP, PORT))
        server_socket.listen(QUEUE_SIZE)
        logging.info(f"Listening for connections on port {PORT}")
        print(f"Listening for connections on port {PORT}\n")

        while True:
            client_socket, client_address = server_socket.accept()
            try:
                logging.info(f"New connection received from {client_address[0]}:{client_address[1]}")
                client_socket.settimeout(SOCKET_TIMEOUT)
                handle_client(client_socket)
            except socket.error as err:
                logging.exception(f"Socket error: {str(err)}")
                print('received socket exception - ' + str(err))
            finally:
                logging.info(f"Connection closed for {client_address[0]}:{client_address[1]}")
                client_socket.close()
    except socket.error as err:
        logging.exception(f"Server socket error: {str(err)}")
        print('received socket exception - ' + str(err))
    finally:
        logging.info("Server socket closed")
        server_socket.close()


if __name__ == "__main__":
    logging.basicConfig(
        filename='server.log',
        level=logging.INFO,
        filemode="w",
        format="%(asctime)s %(levelname)s %(message)s"
    )

    assert "html" in CONTENT_TYPES
    assert CONTENT_TYPES.get("jpg") == "image/jpeg"
    assert CONTENT_TYPES.get("png") == "image/png"
    assert get_content_type("a.html") == CONTENT_TYPES["html"]
    assert get_content_type("a.JPG") == CONTENT_TYPES["jpg"]
    assert get_content_type("a.css") == "text/css"
    assert get_content_type("a.js") == "text/javascript; charset=UTF-8"
    assert get_content_type("a.txt") == "text/plain"
    assert get_content_type("a.ico") == "image/x-icon"
    assert get_content_type("a.gif") == "image/jpeg"
    assert get_content_type("a.png") == "image/png"

    header = build_http_header("200 OK", "text/html", 10)
    assert header.startswith("HTTP/1.1 ")
    assert header.endswith("\r\n\r\n")
    assert "Content-Length: 10" in header
    assert "Content-Type: text/html" in header

    assert validate_http_request("GET / HTTP/1.1\r\n\r\n")[0] is True
    assert validate_http_request("GETT / HTTP/1.1\r\n\r\n")[0] is False

    print("All asserts passed")


    main()
