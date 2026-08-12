import socket
import sys


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", int(sys.argv[1])))
listener.listen()
while True:
    connection, _ = listener.accept()
    with connection:
        connection.recv(1024)
        connection.sendall(b"tcp-ok\n")
