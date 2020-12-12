
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15


# Takes an input file name and checks if file exists
# If so, open and return encrypted data
def encryptFile(inputFileName, rPublicKey):
    encryptedData = bytearray()
    # Check if file exists
    try:
        inputFile = open(inputFileName, "rb")
    except (OSError, IOError):
        print("File not found")
        return
    if os.path.getsize(inputFileName) == 0:
        print("File is empty")
        return
    # Read from file and close
    inputData = inputFile.read()
    inputFile.close()

    # Create the message signature
    h = SHA256.new(inputData)
    signature  = pkcs1_15.new(RSA.import_key(open("private.pem").read())).sign(h)

    # Encrypt
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rPublicKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(inputData)
    [encryptedData.extend(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    return (encryptedData, signature)


# Decrypt Data in array
def decryptFile(data, signature, sPublicKey):
    global rPrivateKey
    decryptedData = bytearray()

    data = bytes(data)
    # Decode the 4 variables made in encryption with User's Private Key
    sizeData = rPrivateKey.size_in_bytes()
    enc_session_key = data[0 : sizeData]
    nonce = data[sizeData : sizeData + 16]
    tag = data[sizeData + 16 : sizeData + 32]
    ciphertext = data[sizeData + 32:]

    # Decrypt the message
    cipher_rsa = PKCS1_OAEP.new(rPrivateKey)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decryptedData = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Verify with signature
    try:
        h = SHA256.new(decryptedData)
        pkcs1_15.new(sPublicKey).verify(h, signature)
    except (ValueError, TypeError):
        return False

    return decryptedData
