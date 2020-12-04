import socket

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    mask = ip.split('.')
    mask = mask[0] + '.' + mask[1] + '.' + mask[2] + '.255'
    return (ip, mask)

host = '10.0.0.233'
port = 4000

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (host, port)
print('connecting to %s port %s' % server_address)
sock.connect(server_address)
try:
    # Send data
    message = 'Hello.'
    print('sending "%s"' % message)
    sock.sendall(message.encode())
    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    while amount_received < amount_expected:
        data = sock.recv(32)
        amount_received += len(data)
        print('received "%s"' % data)
finally:
    print('closing socket')
    sock.close()
