import socket
import sys


with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2) as connection:
    connection.sendall(b"probe\n")
    if connection.recv(32) != b"tcp-ok\n":
        raise SystemExit("unexpected TCP response")
