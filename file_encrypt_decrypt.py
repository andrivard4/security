
import os
import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15



# Takes an input file name and checks if file exists
# If so, open and return encrypted data
def getFileInput(inputFileName, rPublicKey):
    global key
    firstEncryptData = bytearray()
    firstEncryptData = bytearray()

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
    print("Input File: ", inputData)

    # Encrypt
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rPublicKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(inputData)
    print("Enc:", enc_session_key, "nonce: ", cipher_aes.nonce, "tag: ", tag, "cipher: ", ciphertext)
    [firstEncryptData.extend(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    # print("First Encrypt: ", firstEncryptData)

    # Encode with User's Private Key
    h = SHA256.new(inputData)
    secondEncryptData = pkcs1_15.new(RSA.import_key(open("private.pem").read())).sign(h)
    # print("Second Encrypt: ", secondEncryptData)

    # Used for testing purposes
    # temp = decryptData2(inputSendData)
    temp = decryptData(firstEncryptData, RSA.import_key(open("reciever.pem").read()), secondEncryptData)
    return (firstEncryptData, secondEncryptData)


# Decrypt Data in array
def decryptData(data, sPublicKey, signature):
    global rPrivateKey
    firstDecryptionData = bytearray()

    data = bytes(data)
    # print("bytes: ", data)
    # Decode the 4 variables made in encryption with User's Private Key
    sizeData = rPrivateKey.size_in_bytes()
    enc_session_key = data[0 : sizeData]
    nonce = data[sizeData : sizeData + 16]
    tag = data[sizeData + 16 : sizeData + 32]
    ciphertext = data[sizeData + 32:]
    print("Enc:", enc_session_key, "nonce: ", nonce, "tag: ", tag, "cipher: ", ciphertext)

    cipher_rsa = PKCS1_OAEP.new(rPrivateKey)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    firstDecryptionData = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print("First Decrypt: ", firstDecryptionData)

    # Decode with Sender's Public Key
    #encryptor = PKCS1_OAEP.new(sPublicKey)
    #decoded_encrypted_msg = firstDecryptionData
    #secondDecryptionData = encryptor.decrypt(decoded_encrypted_msg)

    try:
        h = SHA256.new(firstDecryptionData)
        pkcs1_15.new(sPublicKey).verify(h, signature)
        print ("The signature is valid.")
    except (ValueError, TypeError):
        print("I'm sorry for your loss")
        exit(1)

    return firstDecryptionData






# main
# Used for testing purposes
rPublicKey = RSA.import_key('-----BEGIN PUBLIC KEY-----\n\
                            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCjgNv/GSm7IX98kNNkQ\
                            eI+/pIOChPGU5sVGeD9k7YM+T6VWVZwig1kqESE9sUd3gREp5U6QGKIlNbjV7yh/\
                            Vg/JzqhC4NfhZUNT1wNRYy3SK6NEESkZfDK5vGjMG1pzPg5WebPXcl0+dXk+uavs\
                            N5FlYMSBHQF7OSu0Ve/WhMtAkv8O7wcxoFo3+fWlaMOzo4eVCWo2hYYa1I3HgFMJ\
                            3mpDZF2ouCsw01VsiMKXVcXNlOhw30lep+CqNjF8yZoX7KtB682ptwAJEAKukp64\
                            yCsys51A60RDD1+Ur5xZwKh++Zq7bFb2x7EdUiK099FZgvHcREIRyy+9ZYJWC90u\
                            iwIDAQAB\n\
                            -----END PUBLIC KEY-----')
rPrivateKey = RSA.import_key("-----BEGIN PRIVATE KEY-----\n\
                            MIIEowIBAAKCAQEAqCjgNv/GSm7IX98kNNkQeI+/pIOChPGU5sVGeD9k7YM+T6\
                            VWVZwig1kqESE9sUd3gREp5U6QGKIlNbjV7yh/Vg/JzqhC4NfhZUNT1wNRYy3SK6NE\
                            ESkZfDK5vGjMG1pzPg5WebPXcl0+dXk+uavsN5FlYMSBHQF7OSu0Ve/WhMtAkv8O\
                            7wcxoFo3+fWlaMOzo4eVCWo2hYYa1I3HgFMJ3mpDZF2ouCsw01VsiMKXVcXNlOhw\
                            30lep+CqNjF8yZoX7KtB682ptwAJEAKukp64yCsys51A60RDD1+Ur5xZwKh++Zq7\
                            bFb2x7EdUiK099FZgvHcREIRyy+9ZYJWC90uiwIDAQABAoIBACe/zcxCZplmmXfM\
                            E89oNfQBqr/VFE+fmV55aGB5P77DBMIn54ICD8hzlbWJ4X7b0VxRddFN4lLoVRpf\
                            UDahoIPz5HS0omZqsU1R/mn3T1A93w3QoIDb8bnBddUbApA+r7oOApPvFnDiqKZ1\
                            HAYgpQw3krquiISWOo33jj+4G0G1Nagjx5JY6xaKWARtDuAXOnCur720uSY2vZOm\
                            qw/oPLuJG4W/uxcywJKwTbVKf9uZpSJ99/pihLNezcW/hONR+NWr+ROZ+GpJxwc7\
                            vlINEgy8JUNCh1SepjSzLUcc0eJ62g5hwChJhbvCY9l5SY40CWPQCVS1DG8ZzgFg\
                            BcKipXECgYEAxwZG9XNDf80IErlLYlWUKyBzM5nioMb+fba2Cs3pBRkLT8ypCDfl\
                            akXKjdHxrdUktKyGv928RQSNiujI1zlfUSvNZukIusX9lJYgY2AwZY1fsDDNVjjk\
                            fPFvWNpGHQcX07yrnuhiwFoyzQXvfl2PZA/aSq7/lhtcAdyaVY381RsCgYEA2Eyi\
                            sArZFEy9qE822nWy6pDTlA3ZjWIwVMVlVoMdNQ2WsKbDnBTtcafcYdcHS0fGObuW\
                            n0KrMwn+4fwbuD9ulqvEYtahNKPzDnlkWJoxxnAxYR+XEZHgrnjN2nqJn1FFTh97\
                            J0oL9X7eG7/y0GtQ+oiXscMHOLMSAYhT0XuyU1ECgYBjUP6X/azxWZ9tuImlyI7n\
                            9omGdoRhNuxIT6UIPzjJEnZSnA69yybwoWMy4lF4LaTjhDS6CiypRFxdtUyEGl02\
                            ZGVbtW5lxeeE/mWrMZT1GFdn1PKi1EExGEo4TLQwSBnbz4rVAaJF2rz/Ercwl/+2\
                            LzL/kdR5U63WP//EMda5gQKBgE+ZdE2A0H5t92XXMQKYSe2UuqhDqIolVk/8DN0X\
                            h0oc5BXCaT4pXXB0K+A9t8t2cHaSmE2nxUUVKp2Tn8fgYBxGvhD5l3290BbFia4p\
                            oKO8ag+qBnhKzPqoLml2qurch7rGTxYYY+pGdAqWSw90TurEFb8vXJr7G2dA+kef\
                            U/LhAoGBAL7sStftfKbXGgQ4EnTbck726v3B3t91POKlIKiuObuJ58zsVZV75093\
                            Cl7lNfTGrpm+9H4a0TVJmtzdERVpW5MVypuR7RBXRxi4FwOsqEhDIzHFJOtOhkfp\
                            nNEu2sAuNni/mo/ZaktqDkamBTSBaGV6QE+0QZuSIbT14PXGnOA0\n\
                            -----END PRIVATE KEY-----")


temp, temp2 = getFileInput("temp.txt", rPublicKey)

































# Takes an input file name and checks if file exists
# If so, open and return encrypted data
def getFileInput2(inputFileName):
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
    ciphertext, tag = cipher_aes.encrypt_and_digest(inputData)
    [inputSendData.append(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    # Used for testing purposes
    temp = decryptData2(inputSendData)
    return inputSendData


# Decrypt Data in array
def decryptData2(data):
    global key

    # Start Decryption
    private_key = key.export_key()
    enc_session_key = data[0]
    nonce = data[1]
    tag = data[2]
    ciphertext = data[3]
    print ("SeshKey: ", enc_session_key)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    fileData = cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    return fileData




# temp = getFileInput2("temp.txt")
