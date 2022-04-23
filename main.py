"""\
A HTTP(S) server written entirely in Python3 using the socket lib.

Format for creating an environment containing all relevant files:

PATH/TO/SCRIPTS/
    main.py -> This file.
    metadata.txt -> the Format is `FQDN;PORT;PATH/TO/CERTIFICATE/FILES/;PATH/TO/CONTENT/;`.

PATH/TO/CONTENT/
    api/ -> You can put api here, but it is not necessary.
        index.html or index.py -> Also not necessary, path is `http(s)://FQDN/api/`.

    exclude.glob -> A newline-separated list of glob patterns to hide files. `api/**`, `error.html` and `exclude.glob` are automatically added to this.
    index.html or index.py -> The homepage, path is `http(s)://FQDN/`.
    error.html -> A template for creating error pages: `{NUM}` is replaced by the error number, `{MSG}` is replaced by the error message.

    [All other folders, html, css, and other content goes here]

PATH/TO/CERTIFICATE/FILES/
    FQDN.crt -> The crt file.
    FQDN.key -> The key file.

Note: All content generating files (E.g., those in /api/) should have a return type of `tuple[str | bytes, str, HTTPStatus]` (content, mimetype, status)
"""

from typing import TYPE_CHECKING, Any, Mapping, Optional, TypedDict, overload, Protocol
from socket import AF_INET, IPPROTO_TCP, SOCK_STREAM, gethostbyname, socket
from logging import INFO, basicConfig, error, info as log, warning as warn
from requests.structures import CaseInsensitiveDict
from ssl import Purpose, create_default_context
from psutil import NoSuchProcess, process_iter
from urllib.parse import urlparse, parse_qs
from mimetypes import add_type, guess_type
from http import client, HTTPStatus
from email.utils import formatdate
from lxml.html import fromstring
from urllib3 import HTTPResponse
from re import IGNORECASE, split
from threading import Thread
from time import sleep, time
from itertools import chain
from fnmatch import fnmatch
from importlib import util
from chardet import detect
from os.path import exists
from select import select
from os import PathLike

if TYPE_CHECKING:
    from socket import _RetAddress
    
    Content = str | bytes
    MimeType = str

    class DetectRes(TypedDict):
        encoding: str
        confidence: float
        language: Any

    class Script(Protocol):
        def main(query: dict) -> tuple[Content, MimeType, HTTPStatus]: pass
        def run(query: dict) -> tuple[Content, MimeType, HTTPStatus]: pass

    @overload
    def detect(byte_str) -> DetectRes: pass


with open("metadata.txt") as f:
    DOMAIN, PORT, CERTPATH, CONTENTPATH = f.read().strip().split(";")

with open(CONTENTPATH + "exclude.glob") as f:
    HIDDEN = f.readlines() + "api/**;error.html;exclude.glob".split(";")

basicConfig(format="(%(asctime)s) %(threadName)s (%(levelname)s): %(message)s", level=INFO, datefmt="%Y-%m-%d %H:%M:%S")

context = create_default_context(Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=f"{CERTPATH}{DOMAIN}.crt", keyfile=f"{CERTPATH}{DOMAIN}.key")

add_type("text/css", ".css", True)

try:
    ADDRESS = gethostbyname(DOMAIN)
    PORT = int(PORT)
except:
    ADDRESS = "127.0.0.1"
    PORT = 5000

RESET = False


class HTTPResponseExt(HTTPResponse):
    raw: str
    head: str = ""
    body: "Content" = ""
    text: str = ""
    headers: Optional[Mapping[str, str] | Mapping[bytes, bytes]] = None
    status: int = 0
    ok: bool = True
    reason: Optional[str] = None
    request_url: Optional[str] = None
    encoding: str = "utf-8"


def GetPrintable(string: str) -> str:
    return "".join([c for c in string if c.isprintable() or c in "\n\t"])

def RunAPI(path: str, query: dict) -> tuple["Content", "MimeType", HTTPStatus]:
    spec = util.spec_from_file_location(path.rsplit("/", 1)[-1].rsplit(".", 1)[0], path)
    
    script: "Script" = util.module_from_spec(spec)
    spec.loader.exec_module(script)
    
    try:
        try:
            return script.run(query)
        except AttributeError:
            return script.main(query)
    except client.HTTPException as e:
        raise client.HTTPException(e.args[0]) # stop purposeful errors from returning 500
    except Exception as e:
        warn(f"Internal server error at \x1b[33m{path}\x1b[0m, sending 500:\n\x1b[31m{e}\x1b[0m")

        raise client.HTTPException(500)      

def GetMIMEType(fname: str) -> "MimeType":
    return (guess_type(fname)[0] or "text/plain")

def ProcessAlive(name: str, ip: str, port: list[int]) -> bool:
    try:
        procs = list(chain.from_iterable([[c for c in p.connections("all") if c.laddr.ip == ip and c.laddr.port in port and c.status == name] for p in process_iter()]))
    except (ProcessLookupError, NoSuchProcess):
        procs = []

    return bool(procs)

def IsHTML(text: str) -> bool:
    return fromstring(text).find(".//*") is not None

def IsAlive(connection: socket, timeout: Optional[int]=None) -> bool:
    try:
        r = list(chain.from_iterable(select([connection], [connection], [], 5)))
    except:
        r = []

    return connection in r and (True if timeout is None else time() - timeout < 5)

def WaitReadable(connection: socket, timeout: Optional[float]=None) -> bool:
    t = time()

    while connection not in select([connection], [], [], 0)[0]:
        if time() - t > timeout or not IsAlive(connection):
            warn("Connection timed out...")

            return False

    return True

def FilterConnection(server: socket, blacklist: list["_RetAddress"]=[]) -> Optional[tuple[socket, "_RetAddress"]]:
    connection, address = server.accept()

    if address in blacklist:
        log(f"Denied connection request to port \x1b[33m{PORT}\x1b[0m from client at \x1b[33m{address[0]}:{address[1]}\x1b[0m.")

        connection.close()

        raise ConnectionRefusedError()

    log(f"Accepted connection request to port \x1b[33m{PORT}\x1b[0m from client at \x1b[33m{address[0]}:{address[1]}\x1b[0m.")

    return connection, address

def ParseHTTP(raw: bytes) -> HTTPResponseExt:
    raw = b"\n".join(raw.splitlines()) # normalise line endings

    try:
        head, body = raw.split(b"\n\n", 1)
    except:
        head, body = raw, b""

    if b"content-type" in head:
        encoding = head.split(b"charset", 1)[-1].split(b"\n")[0].strip().removeprefix(b"=").strip().decode("utf-8")
    elif b"content-encoding" in head:
        encoding = head.split(b"content-encoding", 1)[-1].split(b"\n")[0].strip().decode("utf-8")
    else:
        encoding = (detect(raw)["encoding"] or "utf-8")

    text = raw.decode(encoding)

    head = head.decode(encoding).lower().strip()
    status = head.split("\n")[0].strip()
    headers = [h.split(":", 1) for h in head.split("\n")[1:] if h.strip()]
    headers = CaseInsensitiveDict({k.strip():v.strip() for k, v in headers})

    headers["content-encoding"] = encoding

    status_code = [int(d) for d in status.split() if d.isdecimal()]

    if status_code:
        status_code = status_code[-1]
        reason = status.rsplit(str(status_code), 1)[-1].strip().upper()
    else:
        status_code = 200
        reason = "OK"

    if split("http/", text.split("\n", 1)[0], 1, IGNORECASE)[0].strip():
        url = split("http/", text.split("\n", 1)[0], 1, IGNORECASE)[0].strip().split(maxsplit=1)[-1].strip()
    else:
        url = None

    res = HTTPResponseExt(body=body, headers=list(headers.items()), status=status_code, reason=reason, request_url=url)
    res.raw = raw
    res.head = head
    res.body = body
    res.text = text
    res.headers = headers
    res.status = status_code
    res.ok = status_code < 400
    res.reason = reason
    res.request_url = url
    res.encoding = encoding

    return res

def ResetSocket(s: socket, delay: float=0) -> None:
    s.close()

    log(f"Successfully closed socket.")

    return sleep(delay)

def SendShutdown(connection: socket, recipient: str) -> bool:
    try:
        connection.send(
            b"HTTP/1.1 408 REQUEST TIMEOUT\nConnection: close\nContent-Type: text/plain\nContent-Length: 0"
        )

        log(f"Successfully sent packet(s) to \x1b[33m{recipient}\x1b[0m.")
        log(f"Closing connection with \x1b[33m{recipient}\x1b[0m...")

        return True
    except:
        warn(f"Failed to send packet(s) to \x1b[33m{recipient}\x1b[0m.")
        log(f"Closing connection with \x1b[33m{recipient}\x1b[0m...")

        return False

def CreateHTTP(body: Optional["Content"]=None, method: Optional[str]=None, url: Optional[PathLike]=None, httpversion: float=1.1, status: HTTPStatus=HTTPStatus(200), headers: Mapping[str, str]={}, autolength: bool=True) -> tuple[bytes, int]:
    if type(headers) != CaseInsensitiveDict:
        headers = CaseInsensitiveDict(headers)

    headers["Date"] = (headers.get("date") or formatdate(timeval=None, localtime=False, usegmt=True))
    headers["Connection"] = (headers.get("connection") or "close")

    if body is None:
        body, status = "", HTTPStatus.NO_CONTENT

    if autolength:
        headers["Content-Length"] = str(len(body))

    if type(body) != bytes:
        body = body.encode("utf-8")

    headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    headers["Service-Worker-Allowed"] = "/"

    head = f"{(method or '').upper()}{(url + ' ' or '/ ') if method else ''}HTTP/{httpversion} {status._value_} {status.phrase}{chr(10) if len(headers) else ''}{chr(10).join([f'{k}: {v}' for k, v in headers.items()])}\n\n"

    head = head.encode(detect(body)["encoding"] or "utf-8")

    return head + body, status._value_


def ServerSocket(connection: socket, address: "_RetAddress"):
    client_IP = "%s:%s" % address # e.g., "127.0.0.1:8080"

    with connection:
        try:
            rec = time()

            if not WaitReadable(connection, 5):
                warn(f"Connection with client at \x1b[33m{client_IP}\x1b[0m timed out: closing connection...")

                raise ConnectionAbortedError

            while IsAlive(connection, rec):
                rdata, status, post = b"", 0, {}

                connection.settimeout(0.1)

                while select([connection], [], [], 0)[0] and IsAlive(connection, rec): # connection is ready to read
                    rdata += connection.recv(4096)

                connection.settimeout(None)

                if len(rdata) and IsAlive(connection, rec): # succesfully recieved data
                    try:
                        req = ParseHTTP(rdata)
                    except client.HTTPException as e:
                        warn("Client sent bad request, sending 400")

                        status = e.args()

                    sleep(0.1)

                    try:
                        if status:
                            raise client.HTTPException(status)

                        log(f"Successfully received packet(s) from client at \x1b[33m{client_IP}\x1b[0m:\n\t" + ("\x1b[32m" if req.ok else "\x1b[31m") + GetPrintable(req.text).replace("\n", "\n\t") + "\x1b[0m")

                        headers = dict(req.headers)

                        if "close" in (headers.get("connection") or []):
                            SendShutdown(connection, client_IP)
                            break

                        elif req.head.startswith("get"):
                            if req.request_url:
                                path = (req.request_url.replace("../", "").strip("/") or "index")
                                post = parse_qs(urlparse(path).query)
                                path = path.split("?", 1)[0].strip()
                            else:
                                path = "index"
                            
                            if path == "api": # root api dir
                                path += "/index"

                            if "." not in path.rsplit("/", 1)[-1]:
                                if exists(CONTENTPATH + path + ".html"):
                                    path += ".html"
                                elif exists(CONTENTPATH + path + ".py"):
                                    path += ".py"

                        if path.endswith(".py"):
                            with open(CONTENTPATH + path) as f:
                                content, mimetype, status = RunAPI(CONTENTPATH + path, post)
                                # note that RunAPI either returns or raises HTTPException

                        else:
                            for p in HIDDEN:
                                if fnmatch(path, p.strip()):
                                    warn(f"Couldn't find file {CONTENTPATH}{path}, sending 404")

                                    raise client.HTTPException(404)

                            try:
                                with open(CONTENTPATH + path) as f:
                                    content, status = f.read(), HTTPStatus(200)
                            except UnicodeDecodeError:
                                with open(CONTENTPATH + path, "rb") as f:
                                    content, status = f.read(), HTTPStatus(200)

                            mimetype = GetMIMEType(CONTENTPATH + path)
                    except Exception as e:
                        if type(e) == client.HTTPException: 
                            status: int = e.args[0]
                        elif type(e) == FileNotFoundError:
                            status = 404
                        else:
                            warn(f"Internal server error, sending 500:\n\x1b[31m{e}\x1b[0m")

                            status = 500

                        with open(f"{CONTENTPATH}error.html") as f:
                            content = f.read().format(NUM=status, MSG=client.responses.get(status))

                        mimetype, status = "text/html", HTTPStatus(status)

                    resp, status = CreateHTTP(content, status=status, headers={"Content-Type": mimetype})

                    rec = time()
                else:
                    resp = None

                if resp and select([], [connection], [], 0)[1] and len(rdata) and IsAlive(connection, rec):
                    connection.send(resp)
                    log(f"Successfully sent packet(s) to client at \x1b[33m{client_IP}\x1b[0m:\n\t" + ("\x1b[32m" if status < 400 else "\x1b[31m") + GetPrintable(resp.decode("utf-8", errors="replace")).replace("\n", "\n\t") + "\x1b[0m")

                    rec = time()

            sleep(0.1)

            log(f"Client at \x1b[33m{client_IP}\x1b[0m closed connection: closing socket...")
        except ConnectionError:
            log(f"Client at \x1b[33m{client_IP}\x1b[0m closed connection: closing socket...")
        except ConnectionAbortedError:
            pass

    log(f"Successfully closed socket.")

def Server():
    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)

    if RESET:
        return ResetSocket(server)

    server.bind((ADDRESS, PORT))
    log(f"Bound to \x1b[33m{ADDRESS}\x1b[0m on port \x1b[33m{PORT}\x1b[0m.")

    connections = []

    while True:
        server.listen()
        log(f"Listening on \x1b[33m{ADDRESS}:{PORT}\x1b[0m.")

        try:
            connection, address = FilterConnection(server) # chooses a client to connect to.

            connections.append(Thread(name=f"Server-{address[0]}:{address[1]}", target=ServerSocket, args=(context.wrap_socket(connection, server_side=True), address), daemon=True))

            connections[-1].start()
        except ConnectionRefusedError: # client is on blacklist
            continue
        except OSError as e:
            return error(e)  


if __name__ == "__main__":
    t = time()

    while ProcessAlive("TIME_WAIT", ADDRESS, [4242, PORT]) and not RESET:
        log(f"\rTIME_WAIT is still active, waiting for it to exit (time elapsed = \x1b[33m{round(time() - t, 2)}s\x1b[0m).     \x1b[A")

    Server()
