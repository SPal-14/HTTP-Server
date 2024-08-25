# Uncomment this to pass the first stage
import asyncio
import argparse
import re
from asyncio.streams import StreamWriter, StreamReader
from pathlib import Path
import socket
import threading
from threading import Thread
import sys

async def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # First & Second stage :-
    
    #server_socket = socket.create_server(("localhost", 4221), reuse_port=True)
    #server_socket.accept() # wait for client
    #server_socket.accept()[0].sendall(b"HTTP/1.1 200 OK\r\n\r\n")
    
    # Third stage :-
    
    # server_socket: socket.socket = socket.create_server(("localhost", 4221), reuse_port=True)
    # client: socket.socket
    # client, addr = server_socket.accept()
    # data: str = client.recv(1024).decode()
    # request_data: list[str] = data.split("\r\n")
    # response: bytes = "HTTP/1.1 200 OK\r\n\r\n".encode()
    # if request_data[0].split(" ")[1] != "/":
    #     response = "HTTP/1.1 404 Not Found\r\n\r\n".encode()
    # client.send(response)
    # client.close()
    # server_socket.close()

    # Fourth stage :-

    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.bind(("localhost", 4221))
    #     s.listen()
    #     conn, addr = s.accept()
    #     while True:
    #         data = conn.recv(1024)
    #         request, headers = data.decode().split("\r\n", 1)
    #         method, target = request.split(" ")[:2]
    #         if not data:
    #             break
    #         if target == "/":
    #             response = b"HTTP/1.1 200 OK\r\n\r\n"
    #         elif target.startswith("/echo/"):
    #             value = target.split("/echo/")[1]
    #             response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(value)}\r\n\r\n{value}".encode()
    #         else:
    #             response = b"HTTP/1.1 404 Not Found\r\n\r\n"
    #         conn.sendall(response)

    # Fifth stage :-

#     server_socket = socket.create_server(("localhost", 4221), reuse_port=True)
#     threads = []
#     while 1:
#         conn, addr = server_socket.accept()  # wait for client
#         t = Thread(target=handle_client, args=[conn])
#         threads.append(t)
#         t.run()

# def reply(req, code, body="", headers={}):
#     b_reply = b""
#     match code:
#         case 200:
#             b_reply += b"HTTP/1.1 200 OK\r\n"
#         case 404:
#             b_reply += b"HTTP/1.1 404 Not Found\r\n"
#         case 500:
#             b_reply += b"HTTP/1.1 500 No\r\n"
#     if not "Content-Type" in headers:
#         headers["Content-Type"] = "text/plain"
#     if body != "":
#         headers["Content-Length"] = str(len(body))
#     for key, val in headers.items():
#         b_reply += bytes(key, "utf-8") + b": " + bytes(val, "utf-8") + b"\r\n"
#     b_reply += b"\r\n" + bytes(body, "utf-8")
#     return b_reply

# def handle_request(conn, req):
#     if req["path"] == "/":
#         return reply(req, 200)
#     if req["path"].startswith("/echo/"):
#         return reply(req, 200, req["path"][6:])
#     if req["path"] == "/user-agent":
#         ua = req["headers"]["User-Agent"]
#         return reply(req, 200, ua)
#     return reply(req, 404)

# def parse_request(bytes):
#     output = {"method": "", "path": "", "headers": {}, "body": ""}
#     lines = bytes.decode("utf-8").split("\r\n")
#     if len(lines) < 3:
#         return None
#     reqLine = lines[0].split(" ")
#     if (not reqLine[0]) or reqLine[0] not in ["GET", "POST", "PUT", "HEAD"]:
#         return None
#     if (not reqLine[1]) or reqLine[1][0] != "/":
#         return None
#     output["method"] = reqLine[0]
#     output["path"] = reqLine[1]
#     # Ignore HTTP version
#     lines = lines[1:]
#     c = 0
#     for l in lines:
#         if l == "":
#             break
#         headLine = l.split(":")
#         output["headers"][headLine[0]] = headLine[1].lstrip()
#         c += 1
#     output["body"] = lines[c + 1]
#     return output

# def handle_client(conn):
#     byte = []
#     try:
#         while (byte := conn.recv(1024)) != b"":
#             parsed_req = parse_request(byte)
#             if parsed_req == None:
#                 conn.send(str.encode("HTTP/1.1 500 No\r\n\r\n"))
#                 return conn.close()
#             # Recv & parsed request
#             conn.send(handle_request(conn, parsed_req))
#             return conn.close()
#     except Exception as e:
#         print("handle_client err", e)
#         conn.close()

    # Sixth stage :-

#     s = socket.socket()
#     s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
#     server_address = ("localhost", 4221)
#     s.bind(server_address)
#     s.listen()
#     while True:
#         conn, addr = s.accept()
#         #c_handler(conn, addr)
#         # c_handler(conn, addr)
#         threading.Thread(target=c_handler, args=(conn, addr)).start()

# def drecv(conn, buffersize):
#     data = conn.recv(buffersize)
#     try:
#         data = data.decode()
#     except:
#         return -1
#     finally:
#         return data
# def dsend(conn, data, buffersize=4096):
#     conn.send(data.encode())
# def status(index, raw=""):
#     ok = "HTTP/1.1 200 OK\r\n"
#     notok = "HTTP/1.1 404 Not Found\r\n\r\n"
#     context = "Content-Type: text/plain\r\nContent-Length: "
#     # context="HTTP/1.1 200 OK\r\n\r\nContent-Type: text/plain\r\nContent-Length: "
#     if index == "/":
#         content = "Default page"
#         mes = ok + context + str(len(content)) + "\r\n" * 2 + content + "\r\n" * 2
#     elif index == "/echo/abc/":
#         content = "abc"
#         mes = ok + context + str(len(content)) + "\r\n" * 2 + content + "\r\n" * 2
#         # return context+str(len("abc"))+"\r\n"*2+"abc"+"\r\n"*2
#     elif index[0:6] == "/echo/":
#         content = index[6:]
#         mes = ok + context + str(len(content)) + "\r\n" * 2 + content + "\r\n" * 2
#     elif index == "/user-agent":
#         content = raw.split("\r\n")[2].split(" ", 1)[1]
#         mes = ok + context + str(len(content)) + "\r\n" * 2 + content + "\r\n" * 2
#     else:
#         # return "HTTP/1.1 404 Not Found\r\n\r\n"
#         content = "Page was not found"
#         mes = notok + context + str(len(content)) + "\r\n" * 2 + content + "\r\n" * 2
#     return mes
# def c_handler(conn, addr, buffersize=4096):
#     def message(data):
#         print("sending message: " + str(data))
#         return dsend(conn, data)
#     data = drecv(conn, buffersize)
#     if data != 0 or data != -1:
#         print(data)
#         # dsend(conn, message)
#         print("data: \n")
#         print(data)
#         p1 = data.split("\r\n")[0].split()[1]
#         message(status(p1, data))
#         """
#         if p1 == "/":
#             message("HTTP/1.1 200 OK\r\n\r\n")
#         elif p1 == "/echo/abc":
#             #message("abc
#             mes="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
#             content="abc"
#             mes+=str(len(abc))+ "r\n"*2
#             mes+=content+"\r\n"*2
#             message(mes)
#         else:
#             message("HTTP/1.1 404 Not Found \r\n\r\n")
#         """
#     else:
#         message(status())

    # Seventh stage :-

    # def handle_req(client, addr):
    #     data = client.recv(1024).decode()
    #     req = data.split("\r\n")
    #     path = req[0].split(" ")[1]
    #     if path == "/":
    #         response = "HTTP/1.1 200 OK\r\n\r\n".encode()
    #     elif path.startswith("/echo"):
    #         response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(path[6:])}\r\n\r\n{path[6:]}".encode()
    #     elif path.startswith("/user-agent"):
    #         user_agent = req[2].split(": ")[1]
    #         response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(user_agent)}\r\n\r\n{user_agent}".encode()
    #     elif path.startswith("/files"):
    #         directory = sys.argv[2]
    #         filename = path[7:]
    #         print(directory, filename)
    #         try:
    #             with open(f"/{directory}/{filename}", "r") as f:
    #                 body = f.read()
    #             response = f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode()
    #         except Exception as e:
    #             response = f"HTTP/1.1 404 Not Found\r\n\r\n".encode()
    #     else:
    #         response = "HTTP/1.1 404 Not Found\r\n\r\n".encode()
    #     client.send(response)
    # server_socket = socket.create_server(("localhost", 4221), reuse_port=True)
    # while True:
    #     client, addr = server_socket.accept()
    #     threading.Thread(target=handle_req, args=(client, addr)).start()

    # Eighth stage :-
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default=".")
    args = parser.parse_args()
    GLOBALS["DIR"] = args.directory
    server = await asyncio.start_server(handle_connection, "localhost", 4221)
    async with server:
        stderr("Starting server...")
        stderr(f"--directory {GLOBALS['DIR']}")
        await server.serve_forever()

GLOBALS = {}
def stderr(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
def parse_request(content: bytes) -> tuple[str, str, dict[str, str], str]:
    first_line, *tail = content.split(b"\r\n")
    method, path, _ = first_line.split(b" ")
    headers: dict[str, str] = {}
    while (line := tail.pop(0)) != b"":
        key, value = line.split(b": ")
        headers[key.decode()] = value.decode()
    return method.decode(), path.decode(), headers, b"".join(tail).decode()
def make_response(
    status: int,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> bytes:
    headers = headers or {}
    msg = {
        200: "OK",
        201: "CREATED",
        404: "NOT FOUND",
    }
    return b"\r\n".join(
        map(
            lambda i: i.encode(),
            [
                f"HTTP/1.1 {status} {msg[status]}",
                *[f"{k}: {v}" for k, v in headers.items()],
                f"Content-Length: {len(body)}",
                "",
                body,
            ],
        ),
    )
async def handle_connection(reader: StreamReader, writer: StreamWriter) -> None:
 #   _, path, headers, _ = parse_request(await reader.read(2**16))
    method, path, headers, body = parse_request(await reader.read(2**16))
    if re.fullmatch(r"/", path):
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        stderr(f"[OUT] /")
    elif re.fullmatch(r"/user-agent", path):
        ua = headers["User-Agent"]
        writer.write(make_response(200, {"Content-Type": "text/plain"}, ua))
        stderr(f"[OUT] user-agent {ua}")
    elif match := re.fullmatch(r"/echo/(.+)", path):
        msg = match.group(1)
        writer.write(make_response(200, {"Content-Type": "text/plain"}, msg))
        stderr(f"[OUT] echo {msg}")
    elif match := re.fullmatch(r"/files/(.+)", path):
        p = Path(GLOBALS["DIR"]) / match.group(1)
        if method.upper() == "GET" and p.is_file():
            writer.write(
                make_response(
                    200,
                    {"Content-Type": "application/octet-stream"},
                    p.read_text(),
                )
            )
        elif method.upper() == "POST":
            p.write_bytes(body.encode())
            writer.write(make_response(201))
        else:
            writer.write(make_response(404))
        stderr(f"[OUT] file {path}")
    else:
        writer.write(make_response(404, {}, ""))
        stderr(f"[OUT] 404")
    writer.close()



if __name__ == "__main__":
    asyncio.run(main())
