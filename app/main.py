# Uncomment this to pass the first stage
import socket


def main():
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 4221))
        s.listen()
        conn, addr = s.accept()
        while True:
            data = conn.recv(1024)
            request, headers = data.decode().split("\r\n", 1)
            method, target = request.split(" ")[:2]
            if not data:
                break
            if target == "/":
                response = b"HTTP/1.1 200 OK\r\n\r\n"
            elif target.startswith("/echo/"):
                value = target.split("/echo/")[1]
                response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(value)}\r\n\r\n{value}".encode()
            else:
                response = b"HTTP/1.1 404 Not Found\r\n\r\n"
            conn.sendall(response)

if __name__ == "__main__":
    main()
