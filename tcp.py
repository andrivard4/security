#!/usr/bin/env python3
# Lots of help taken from: https://github.com/fabrizio8/network-example
# Many much thanks to Fabrizio8

import sys
import os
import json
import ssl
import socket
from time import sleep
from multiprocessing import Process
from socketserver import BaseRequestHandler, TCPServer
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2

########################
# Cassie, Pooja
# GET EMAIL
# Gets current user's hashed email
#
# CHECK FOR ONLINE CONTACTS
# Given a list of ports, send TCP to each with hashed email
# Wait for reply
# Verify reply hash exists in contact email list
# If yes, add contact and port to list of online users
#
# CHECK IF CONTACT
#Check hashed email with emails you have (hashed)
# If a matche, note the port that sent request with the contact that matches
# Send your hashed email back as reply
#########################

# If given an email, return hashed email
# If no email given, return user's hashed email
def getEmail(email):
    # Get own email
    if(!email):
        account_file = open(os.path.expanduser("~") + "/.securedrop/user.log", "r")
        account_data = account_file.read()
        account_file.close()
        account_data = json.loads(account_data)
        email = account_data['email']
    # Return hash email
    return( SHA256.new(email) )
    
# Decrypt contacts file
# For each email within that file, check if recieved hashed email is within
# If not, return False
# If so, return hash of user's email
def checkEmail(newEmail):
    # Decrypt file to find contact emails
    # Get contact file and see if it exists
    try:
        contactfile = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "rb")
    except (OSError, IOError):
        return False
    if os.path.getsize( os.path.expanduser("~") + "/.securedrop/contacts.log" ) == 0:
        return False

    # If contact file exists and there is contnet, decrypt
    enc_session_key, nonce, tag, ciphertext = \
        [ contactfile.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    JSON_data = cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    # Check if email is within JSON_data
    if JSON_data:
        JSON_data = json.loads(JSON_data)
        for email in JSON_data:
            if getEmail(newEmail) == getEmail(email):
                return getEmail();
    return False

    
class tcp_handler(BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        print("Echoing message from: {}".format(self.client_address[0]))
        print(self.data)
        self.request.sendall("ACK from server".encode())


def tcp_listener(port):
    host = "localhost"
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cntx.load_cert_chain('cert.pem', 'cert.pem')

    server = TCPServer((host, port), tcp_handler)
    server.socket = cntx.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except:
        print("listener shutting down")
        server.shutdown()


def tcp_client(port, data):
    host_ip = "127.0.0.1"

    # Initialize a TCP client socket using SOCK_STREAM
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cntx.load_verify_locations('cert.pem')
    cntx.load_cert_chain('cert.pem')

    s = cntx.wrap_socket(s, server_hostname='test.server')

    try:
        # Establish connection to TCP server and exchange data
        s.connect((host_ip, port))
        s.sendall(data.encode())
        # Read data from the TCP server and close the connection
        received = s.recv(1024)
    finally:
        s.close()

    print("Bytes Sent:     {}".format(data))
    print("Bytes Received: {}".format(received.decode()))






