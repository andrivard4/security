from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import json
import getpass
import os

private_key = ""
hashed_password = ""
registered_email = ""
salt = ""
public_key = ""


def getAccountInfo():
    global registered_email
    global salt
    global hashed_password
    global public_key
    account_file = open(os.path.expanduser("~") + "/.securedrop/user.log", "r")
    account_data = account_file.read()
    account_file.close()
    account_data = json.loads(account_data)
    registered_email = account_data['email']
    salt = account_data['credentials'].split(':')[0]
    hashed_password = account_data['credentials'].split(':')[1]
    public_key = RSA.import_key(bytes.fromhex(account_data['pub']))

def autho_user():
    global private_key
    print("Log in for account ", registered_email)
    password = getpass.getpass(prompt='Enter Password: ')
    entered_hash = SHA256.new()
    entered_hash.update(bytes.fromhex(salt) + password.encode("utf8"))
    if (hashed_password == entered_hash.hexdigest()):
        print("Login Success! Decrypting private key...")
        key_file = open(os.path.expanduser("~") + "/.securedrop/private.pem", "rb")
        nonce = key_file.read(16)
        tag = key_file.read(16)
        encrypted_key = key_file.read(-1)
        key_file.close();
        cipher = AES.new(PBKDF2(password, bytes.fromhex(salt), dkLen=16), AES.MODE_EAX, nonce)
        private_key = RSA.import_key(cipher.decrypt_and_verify(encrypted_key,tag))
    else:
        print("Login Failed!")
        exit()

getAccountInfo()
autho_user()
print(private_key.export_key())
