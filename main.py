from typing import IO, TYPE_CHECKING, Any, Iterable, Mapping, NamedTuple, Optional
from socket import AF_INET, IPPROTO_TCP, SOCK_STREAM, gethostbyname, socket
from logging import INFO, basicConfig, info as log, warning as warn
from requests.structures import CaseInsensitiveDict
from psutil import NoSuchProcess, process_iter
from email.utils import formatdate
from lxml.html import fromstring
from urllib3 import HTTPResponse
from re import IGNORECASE, split
from threading import Thread
from time import sleep, time
from itertools import chain
from http import HTTPStatus
from chardet import detect
from select import select
from magic import Magic
from os import PathLike
from uuid import uuid4

if TYPE_CHECKING:
    from socket import _RetAddress


with open("domain.txt") as f:
    DOMAIN = f.read().strip()


basicConfig(format="(%(asctime)s) %(threadName)s: %(message)s", level=INFO, datefmt="%Y-%m-%d %H:%M:%S")

try:
    ADDRESS = gethostbyname(DOMAIN)
    PORT = 8080
except:
    ADDRESS = "127.0.0.1"
    PORT = 5000

RESET = False


class HTTPResponseExt(HTTPResponse):
    raw: str
    head: str = ""
    body: bytes | IO[Any] | Iterable[bytes] | str = ""
    text: str = ""
    headers: Optional[Mapping[str, str] | Mapping[bytes, bytes]] = None
    status: int = 0
    ok: bool = True
    reason: Optional[str] = None
    request_url: Optional[str] = None
    encoding: str = "utf-8"

class Session(NamedTuple):
    start: float
    id: str


def GetMIMEType(fname: str) -> str:
    mime = Magic(mime=True)
    
    return mime.from_file(fname)

def ProcessAlive(name: str, ip: str, port: list[int]) -> bool:
    try:
        procs = list(chain.from_iterable([[c for c in p.connections("all") if c.laddr.ip == ip and c.laddr.port in port and c.status == name] for p in process_iter()]))
    except (ProcessLookupError, NoSuchProcess):
        procs = []

    return bool(procs)

def IsHTML(text: str) -> bool:
    return fromstring(text).find(".//*") is not None

def IsAlive(connection: socket, timeout: int | None=None) -> bool:
    try:
        r = list(chain.from_iterable(select([connection], [connection], [], 5)))
    except:
        r = []

    return connection in r and (True if timeout is None else time() - timeout < 60)

def WaitReadable(connection: socket, timeout: float | None=None) -> bool:
    t = time()

    while connection not in select([connection], [], [])[0]:
        if time() - t > timeout or not IsAlive(connection):
            warn("Connection timed out...")

            return False

    return True

def FilterConnection(server: socket, blacklist: list["_RetAddress"]=[]) -> tuple[socket, "_RetAddress"] | None:
    connection, address = server.accept()

    if address in blacklist:
        log(f"Denied connection request to port {PORT} from client at \x1b[33m{address[0]}:{address[1]}\x1b[0m.")

        connection.close()

        raise ConnectionRefusedError()
    
    log(f"Accepted connection request to port {PORT} from client at \x1b[33m{address[0]}:{address[1]}\x1b[0m.")

    return connection, address

def ParseHTTP(raw: bytes) -> HTTPResponseExt:
    raw = b"\n".join(raw.splitlines()) # normalise line endings
    
    try:
        head, body = raw.split(b"\n\n", 1)
    except:
        head, body = raw, b""

    if b"content-type" in head or b"content-encoding" in head:
        if b"content-type" in head: 
            encoding = head.split(b"charset", 1)[-1].split(b"\n")[0].strip().removeprefix(b"=").strip().decode("utf-8")
        else:
            encoding = head.split(b"content-encoding", 1)[-1].split(b"\n")[0].strip().decode("utf-8")
    else:
        encoding = detect(raw)["encoding"]

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
        connection.send(b"HTTP/1.1 204 NO CONTENT\nConnection: close\nContent-Type: text/plain")
        log(f"Successfully sent packet(s) to {recipient}.")
        log(f"Closing connection with {recipient}...")

        return True
    except:
        warn(f"Failed to send packet(s) to {recipient}.")
        log(f"Closing connection with {recipient}...")

        return False

def CreateHTTP(body: str | bytes | None=None, method: str | None=None, url: PathLike | None=None, httpversion: float=1.1, status: HTTPStatus=HTTPStatus.OK, headers: Mapping[str, str]={}, autolength: bool=True) -> tuple[bytes, int]:
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

    headers["X-Auto-Generated-By"] = "CreateHTTP (c) GoodCoderBBoy 2022"

    head = f"{(method or '').upper()}{(url + ' ' or '/ ') if method else ''}HTTP/{httpversion} {status._value_} {status.phrase}{chr(10) if len(headers) else ''}{chr(10).join([f'{k}: {v}' for k, v in headers.items()])}\n\n"

    head = head.encode(detect(body)["encoding"])

    return head + body, status._value_


# def ServerSocket(connection: socket, address: _RetAddress):

def Server():
    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)

    if RESET:
        return ResetSocket(server)

    server.bind((ADDRESS, PORT))
    log(f"Bound to \x1b[33m{ADDRESS}\x1b[0m on port \x1b[33m{PORT}\x1b[0m.")

    while True:
        server.listen()
        log(f"Listening on \x1b[33m{ADDRESS}:{PORT}\x1b[0m.")

        try:
            connection, address = FilterConnection(server) # chooses a client to connect to.
            client_IP = "%s:%s" % address # e.g., "127.0.0.1:8080"
        except ConnectionRefusedError: # client is on blacklist
            continue
        except OSError as e:
            return warn(e)
        
        session = Session(time(), f"{client_IP}-{str(uuid4())}")

        log(f"Started session {session}")

        with connection:
            try:
                if not WaitReadable(connection, 5):
                    break

                rec = session.start

                while IsAlive(connection, rec):
                    rdata = [b""]

                    while select([connection], [], [], 0)[0] and IsAlive(connection, rec): # connection is ready to read
                        to = connection.gettimeout()
                        connection.settimeout(0)

                        rdata.append(connection.recv(1024))

                        connection.settimeout(to)

                    if len(rdata) - 1 and IsAlive(connection, rec): # succesfully recieved data
                        req = ParseHTTP(b"".join(rdata))

                        sleep(0.1)

                        log(f"Successfully received packet(s) from client at \x1b[33m{client_IP}\x1b[0m:\n\t" + ("\x1b[32m" if req.ok else "\x1b[31m") + req.text.replace("\n", "\n\t") + "\x1b[0m")

                        headers = dict(req.headers)

                        if "close" in headers.get("connection"):
                            break

                        elif req.head.startswith("get"):
                            if req.request_url:
                                path = "/" + (req.request_url.strip("/") or "index")
                            else:
                                path = "/index"
                            
                            fpath, fname = path.rsplit("/", 1)

                            if "." not in fname:
                                fname += ".html"

                            try:
                                with open(f"{fpath}/{fname}") as f:
                                    content = f.read()

                                mimetype = GetMIMEType(f"{fpath}/{fname}")
                            except:
                                with open(f"/404.html") as f:
                                    content = f.read()

                                mimetype = "text/html"
                                
                        resp, status = CreateHTTP(content, status=HTTPStatus.NOT_FOUND, headers={"Content-Type": mimetype})
                        
                        rec = time()
                    else:
                        resp = None

                    if resp and select([], [connection], [], 0)[1] and len(rdata) - 1 and IsAlive(connection, rec):
                        connection.send(resp)
                        log(f"Successfully sent packet(s) to client at \x1b[33m{client_IP}\x1b[0m:\n\t" + ("\x1b[32m" if status < 400 else "\x1b[31m") + resp.decode("utf-8").replace("\n", "\n\t") + "\x1b[0m")
                        
                        rec = time()

                sleep(0.1)

                log(f"Client at \x1b[33m{client_IP}\x1b[0m closed connection: closing socket...")
            except ConnectionError:
                log(f"Client at \x1b[33m{client_IP}\x1b[0m closed connection: closing socket...")
            
        log(f"Successfully closed socket.")

def Client():
    client = socket(AF_INET, SOCK_STREAM)

    if RESET:
        return ResetSocket(client, 0.5)

    client.bind((ADDRESS, 4242))
    log("Bound to \x1b[33m%s\x1b[0m on port \x1b[33m%s\x1b[0m." % client.getsockname())

    with client:
        try:
            client.connect((ADDRESS, PORT))
            log(f"Requested connection to \x1b[33m{ADDRESS}\x1b[0m on port \x1b[33m{PORT}\x1b[0m.")

            sleep(0.1)

            if not IsAlive(client):
                raise ConnectionRefusedError()

            client.send(b"HTTP/1.1 200 OK\nContent-Type: text/plain\nConnection: Keep-Alive\n\nHello, world!")
            log(f"Successfully sent packet(s) to server.")
        except ConnectionRefusedError:
            warn(f"Server denied connection to port \x1b[33m{PORT}\x1b[0m: closing socket...")

            return log("Successfully closed socket.")
        except OSError as e:
            return warn(e)

        try:
            if not WaitReadable(client, 2):
                raise ConnectionError

            rdata = [b""]

            while select([client], [], [], 0.1)[0]:
                to = client.gettimeout()
                client.settimeout(0.1)
                
                rdata.append(client.recv(1024))

                client.settimeout(to)

            if len(rdata) - 1  and IsAlive(client): # succesfully recieved data
                resp: HTTPResponseExt = ParseHTTP(b"".join(rdata))

                log(f"Successfully received packet(s) from server:\n\t" + ("\x1b[32m" if resp.ok else "\x1b[31m") + resp.text.replace("\n", "\n\t") + "\x1b[0m")

            SendShutdown(client, "server")
        except ConnectionError:
            sleep(0.1)

            warn(f"Server closed connection to port \x1b[33m{PORT}\x1b[0m unexpectedly: closing socket...")

            return log("Successfully closed socket.")

    log("Successfully closed connection.")


if __name__ == "__main__":
    t = time()

    while ProcessAlive("TIME_WAIT", ADDRESS, [4242, PORT]):
        log(f"\rTIME_WAIT is still active, waiting for it to exit (time elapsed = {round(time() - t, 2)}s).     \x1b[A")

    log("")


    serverT = Thread(target=Server, name="Server", daemon=True)
    # clientT = Thread(target=Client, name="Client", daemon=True)

    serverT.start()
    serverT.join()

    # clientT.start()
    # clientT.join()
    
    sleep(2)
