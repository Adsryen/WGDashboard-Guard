import socket
import sys


client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(2)
client.sendto(b"probe\n", (sys.argv[1], int(sys.argv[2])))
response, _ = client.recvfrom(32)
if response != (sys.argv[3] + "\n").encode("ascii"):
    raise SystemExit("unexpected UDP response")
