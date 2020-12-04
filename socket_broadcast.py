import socket
import time


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
while True:
    s.sendto("HELLLOOO!!".encode(), ('255.255.255.255', 1338))
    time.sleep(5)
