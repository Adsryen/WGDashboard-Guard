import socket
import sys


listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("0.0.0.0", int(sys.argv[1])))
payload = (sys.argv[2] + "\n").encode("ascii")
while True:
    _, address = listener.recvfrom(1024)
    listener.sendto(payload, address)
