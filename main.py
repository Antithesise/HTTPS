from socket import AF_INET, IPPROTO_TCP, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from typing import IO, TYPE_CHECKING, Any, Iterable, Mapping, Optional
from logging import INFO, basicConfig, info as log, warning as warn
from requests.structures import CaseInsensitiveDict
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
from os import PathLike

if TYPE_CHECKING:
    from socket import _RetAddress

basicConfig(format="(%(asctime)s) %(threadName)s: %(message)s", level=INFO, datefmt="%Y-%m-%d %H:%M:%S")

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


def IsHTML(text: str) -> bool:
    return fromstring(text).find(".//*") is not None

def IsAlive(connection: socket) -> bool:
    return connection in chain.from_iterable(select([connection], [connection], [], 5))

def WaitReadable(connection: socket, timeout: float | None=None) -> bool:
    t = time()

    while connection not in select([connection], [], [])[0]:
        if time() - t > timeout or not IsAlive(connection):
            warn("Connection timed out...")

            return False

    return True

def FilterConnection(server: socket, blacklist: list["_RetAddress"] = []) -> tuple[socket, "_RetAddress"] | None:
    connection, address = server.accept()

    if address in blacklist:
        log(f"Denied connection request to port {PORT} from client at {address[0]}:{address[1]}.")

        connection.close()

        raise ConnectionRefusedError()
    
    log(f"Accepted connection request to port {PORT} from client at {address[0]}:{address[1]}.")

    return connection, address

def ParseHTTP(sender: socket, raw: bytes) -> HTTPResponseExt:
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

    raw = b"\n".join(raw.splitlines()) # normalise line endings
    text = raw.decode(encoding)

    head = head.decode(encoding).lower()
    status = head.split("\n")[0].strip()
    headers = [h.split(": ") for h in head.split("\n")[1:]]

    headers = CaseInsensitiveDict({k.strip():v.strip() for k, v in headers})
    headers["content-encoding"] = encoding

    status_code = [int(d) for d in status.split() if d.isdecimal()][-1]
    reason = status.rsplit(str(status_code), 1)[-1].strip().upper()
    if split("http/", text.split("\n", 1)[0], 1, IGNORECASE)[0].strip():
        url = split("http/", text.split("\n", 1)[0], 1, IGNORECASE)[0].strip().split(maxsplit=1)[-1]
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

def ResetSocket(s: socket, delay: float = 0) -> None:
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

def CreateHTTP(body: str | bytes | None=None, method: str | None=None, url: PathLike | None=None, httpversion: float=1.1, status: HTTPStatus=HTTPStatus.OK, headers: Mapping[str, str]={}, autolength: bool=True) -> bytes:
    if type(headers) != CaseInsensitiveDict:
        headers = CaseInsensitiveDict(headers)

    headers["Date"] = (headers.get("date") or formatdate(timeval=None, localtime=False, usegmt=True))
    headers["Connection"] = (headers.get("connection") or "keep-alive")

    if body is None:
        body, status = "", HTTPStatus.NO_CONTENT

    if autolength:
        headers["Content-Length"] = str(len(body))

    if type(body) != bytes:
        body = body.encode("utf-8")

    head = f"{(method or '').upper()}{(url + ' ' or '/ ') if method else ''}HTTP/{httpversion} {status._value_} {status.phrase}{chr(10) if len(headers) else ''}{chr(10).join([f'{k}: {v}' for k, v in headers.items()])}\n\n"

    head = head.encode(detect(body)["encoding"])

    return head + body


def Server():
    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server.bind((ADDRESS, PORT))
    log(f"Bound to {ADDRESS} on port {PORT}.")

    server.listen(1)
    log(f"Listening on {ADDRESS}:{PORT}.")

    if RESET:
        return ResetSocket(server)

    session = 0

    while True:
        session += 1

        try:
            connection, address = FilterConnection(server) # chooses a client to connect to.
            client_IP = f"{address[0]}:{address[1]}" # e.g., "127.0.0.1:8080"
        except ConnectionRefusedError: # client is on blacklist
            continue
        except OSError as e:
            warn(e)

            return ResetSocket(server, 5)

        with connection:
            try:
                if not WaitReadable(connection, 5):
                    break

                while IsAlive(connection):
                    rdata = [b""]

                    while select([connection], [], [], 0)[0] and IsAlive(connection): # connection is ready to read
                        to = connection.gettimeout()
                        connection.settimeout(0.1)

                        rdata.append(connection.recv(1024))

                        connection.settimeout(to)

                    if len(rdata) - 1 and IsAlive(connection): # succesfully recieved data
                        req = ParseHTTP(connection, b"".join(rdata))

                        log(f"Successfully received packet(s) from client at {client_IP}:\n\t" + ("\x1b[32m" if req.ok else "\x1b[31m") + req.text.replace("\n", "\n\t") + "\x1b[0m")

                        headers = dict(req.headers)

                        if "close" in headers.get("connection"):
                            break

                        elif req.head.startswith("get"):
                            pass

                    if select([], [connection], [], 0)[1] and len(rdata) - 1 and IsAlive(connection):
                        resp = CreateHTTP(b"Hello, world!", headers={"Content-Type": "text/plain"})

                        connection.send(resp)
                        log(f"Successfully sent packet(s) to client at {client_IP}.")

                sleep(0.1)

                log(f"Client at {client_IP} closed connection: closing socket...")
            except ConnectionError:
                log(f"Client at {client_IP} closed connection: closing socket...")
            
        log(f"Successfully closed socket.")

def Client():
    client = socket(AF_INET, SOCK_STREAM)
    client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    client.bind(("127.0.0.1", 4242))
    log("Bound to %s on port %s" % client.getsockname())

    if RESET:
        return ResetSocket(client, 0.5)

    with client:
        try:
            client.connect((ADDRESS, PORT))
            log(f"Requested connection to {ADDRESS} on port {PORT}.")

            sleep(0.1)

            if not IsAlive(client):
                raise ConnectionRefusedError()

            client.send(b"HTTP/1.1 200 OK\nContent-Type: text/plain\nConnection: Keep-Alive\n\nHello, world!")
            log(f"Successfully sent packet(s) to server.")
        except ConnectionRefusedError:
            warn(f"Server denied connection to port {PORT}: closing socket...")

            return log("Successfully closed socket.")
        except OSError as e:
            warn(e)

            return ResetSocket(client, 5)

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
                resp: HTTPResponseExt = ParseHTTP(client, b"".join(rdata))

                log(f"Successfully received packet(s) from server:\n\t" + ("\x1b[32m" if resp.ok else "\x1b[31m") + resp.text.replace("\n", "\n\t") + "\x1b[0m")

            SendShutdown(client, "server")
        except ConnectionError:
            sleep(0.1)

            warn(f"Server closed connection to port {PORT} unexpectedly: closing socket...")

            return log("Successfully closed socket.")

    log("Successfully closed connection.")


if __name__ == "__main__":
    serverT = Thread(target=Server, name="Server", daemon=True)
    clientT = Thread(target=Client, name="Client", daemon=True)

    serverT.start()

    clientT.start()
    clientT.join()
    
    sleep(2)
