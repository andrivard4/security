
import os
import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

key = RSA.generate(2048)


# Takes an input file name and checks if file exists
# If so, open and return encrypted data
def getFileInput(inputFileName):
    global key
    inputSendData = []

    # Check if file exists
    try:
        inputFile = open(inputFileName, "rb")
    except (OSError, IOError):
        print("File not found"); return
    if os.path.getsize(inputFileName) == 0:
        print("File is empty"); return
    # Read from file and close
    inputData = inputFile.read()
    inputFile.close()

    # Start encoding
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(key.publickey().export_key()))
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    [inputSendData.append(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    # Used for testing purposes
    # temp = decryptData(inputSendData)
    return inputSendData


# Decrypt Data in array
def decryptData(data):
    global key

    # Start Decryption
    private_key = key.export_key()
    enc_session_key = data[0]
    nonce = data[1]
    tag = data[2]
    ciphertext = data[3]
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    fileData = cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    return fileData

# main
# Used for testing purposes
# temp = getFileInput("temp.txt")
