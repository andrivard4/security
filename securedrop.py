# help from https://pymotw.com/2/socket/tcp.html



from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import json
import getpass
import os
import sys
import socket
import time
from multiprocessing import Process, Manager

# Global Variables
username = "usr"
email = "email"
encrypted_password = ""
salt = 0
password = "Password"
confirm = "conf"
public_key = ""
private_key = ""
JSON_data = json.loads('{"contacts":[]}')
input_name = ""
input_email = ""


# Pooja
def getRegistrationInput():
    # Get user input from command line
    # Save it in the above variables
    global username
    global email
    global password
    global confirm
    username = input('Enter Full Name: ')
    email = input('Enter Email: ')
    password = getpass.getpass(prompt='Enter Password: ')
    confirm = getpass.getpass(prompt='Re-enter Password: ')


# Cassie
# Validate Input from user
def validateRegistrationInput():
    global username
    global email
    global password
    global confirm
    has_digit = 0
    has_symbol = 0
    has_upper = 0
    has_lower = 0
    error = 1
    errormess = ""

    # While there is an error, keep looping
    while error == 1 or errormess != "":
        errormess = ""
        error = 0
        # Check if email is valid
        email_contents = email.split("@")
        if len(email_contents) != 2 or email_contents[1] == "" or email_contents[1][0] == ".":
            errormess += "Email is invalid\n"
            error = 1
        elif len(email_contents[1].split(".")) != 2 or email_contents[1].split(".")[1] == "":
            errormess += "Email is invalid\n"
            error = 1

        # Make sure passwords match
        if password != confirm:
            errormess += "Passwords do not match\n"
            error = 1
        # Get rid of data in confirm variable, no longer used
        confirm = ""

        # Check length of password
        # If length is good, check to see if lower, upper, number, symbol
        #  present in the password
        if len(password) < 8 or len(password) > 100:
            errormess += "Password needs to be 8-100 characters in length\n"
            error = 1
        else:
            for character in password:
                if character.isdigit():
                    has_digit = 1
                if character.islower():
                    has_lower = 1
                if character.isupper():
                    has_upper = 1
                if not character.isalnum() and not character.isspace:
                    has_symbol = 1
                if character.isspace():
                    errormess += "Password cannot contain white space"
                    error = 1
        if (has_digit + has_lower + has_upper + has_symbol) < 3:
            errormess += "Password needs all of the following:\n number, uppercase letter, lowercase letter, symbol\n"
            error = 1

        # If any error occured, call getInput and restart the loop
        # Otherwise continue
        if(errormess == "" and error == 0):
            return
        else:
            print(errormess)
            getRegistrationInput()


# Andrew
# Generate Public key and Private key
def keyGen():
    global private_key
    global public_key
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(os.path.expanduser("~") + "/.securedrop/private.pem", "wb")
    cipher = AES.new(PBKDF2(password, salt, dkLen=16), AES.MODE_EAX)
    encrypted_data, tag = cipher.encrypt_and_digest(private_key)
    file_out.write(cipher.nonce)
    file_out.write(tag)
    file_out.write(encrypted_data)
    file_out.close()

    private_key = RSA.import_key(private_key)
    public_key = RSA.import_key(key.publickey().export_key())


# Andrew
# Encrypt user password
def encryptUserData():
    # Encrypts the user data
    global salt
    global encrypted_password
    global password
    salt = get_random_bytes(2)
    password_hash = SHA256.new()
    keyGen()
    password_hash.update(salt + password.encode("utf8"))
    # we no longer want the unencrypted password to exist
    password = ""
    encrypted_password = password_hash.hexdigest()


# Andrew
# Load ~/.securedrop/user.log and put in email, name, encrypted password, and public key
def loadUserFile():
    user = open(os.path.expanduser("~") + "/.securedrop/user.log", "w")
    user.write(json.dumps({'email': email, 'name': username, 'credentials': salt.hex() + ":" + encrypted_password, 'pub': public_key.export_key().hex()}))
    user.close()


# Andrew
# Checks if account is created
def account_check():
    if os.path.exists(os.path.expanduser("~") + "/.securedrop/user.log"):
        return 1
    os.mkdir(os.path.expanduser("~") + "/.securedrop")
    return 0


# Cassie, Pooja
# Get contact name and email
def getContactInput():
    global input_name
    global input_email
    input_name = input('Enter Contact Name:  ')
    input_email = input('Enter Contact Email:  ')


# Validate email is an email address
# Cassie, Pooja
def validateContactInput():
    global input_email
    error = 1

    # Make sure email has *@*.* where *s are replaced with any character
    while error == 1:
        email_contents = input_email.split("@")
        if len(email_contents) != 2 or email_contents[1] == "" or email_contents[1][0] == ".":
            print("Email is invalid\n")
        elif len(email_contents[1].split(".")) != 2 or email_contents[1].split(".")[1] == "":
            print("Email is invalid\n")
        else:
            error = 0

        if error == 1:
            getContactInput()


# Cassie, Pooja
# Decrypts ~/.securedrop/contacts.log should it exist
def decryptContacts():
    global JSON_data
    # Get contact file and see if it exists
    try:
        contactfile = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "rb")
    except (OSError, IOError):
        return
    if os.path.getsize(os.path.expanduser("~") + "/.securedrop/contacts.log") == 0:
        return
    # If contact file exists and there is contnet, decrypt
    enc_session_key, nonce, tag, ciphertext = \
        [contactfile.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    JSON_data = json.loads(cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8'))


# Cassie, Pooja
# Add a contact to the JSON data
def addContactsToFile():
    global input_name
    global input_email
    global JSON_data
    for email in JSON_data:
        if input_email == email:
            print("This email already exists as a contact.\n")
            return
    list = JSON_data['contacts']
    list.append({'name': input_name, 'email': input_email})
    JSON_data.update({'contacts': list})


# Cassie, Pooja
# Encrypt the contact info with the public key then write it to the contact file
def encryptContacts():
    global input_name
    global input_email
    global JSON_data

    if not os.path.exists(os.path.expanduser("~") + "/.securedrop"):
        os.mkdir(os.path.expanduser("~") + "/.securedrop")
    file_out = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "wb")
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(JSON_data, indent=2).encode('utf-8'))
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()


# Andrew
# Gets information about user account
def getAccountInfo():
    global email
    global salt
    global hashed_password
    global public_key
    global username
    account_file = open(os.path.expanduser("~") + "/.securedrop/user.log", "r")
    account_data = account_file.read()
    account_file.close()
    account_data = json.loads(account_data)
    email = account_data['email']
    username = account_data['name']
    salt = account_data['credentials'].split(':')[0]
    hashed_password = account_data['credentials'].split(':')[1]
    public_key = RSA.import_key(bytes.fromhex(account_data['pub']))


# Andrew
# User login
def autho_user():
    global private_key
    print("Log in for account ", email)
    password = getpass.getpass(prompt='Enter Password: ')
    entered_hash = SHA256.new()
    entered_hash.update(bytes.fromhex(salt) + password.encode("utf8"))
    if (hashed_password == entered_hash.hexdigest()):
        print("Login Success!")
        key_file = open(os.path.expanduser("~") + "/.securedrop/private.pem", "rb")
        nonce = key_file.read(16)
        tag = key_file.read(16)
        encrypted_key = key_file.read(-1)
        key_file.close()
        cipher = AES.new(PBKDF2(password, bytes.fromhex(salt), dkLen=16), AES.MODE_EAX, nonce)
        private_key = RSA.import_key(cipher.decrypt_and_verify(encrypted_key, tag))
    else:
        print("Login Failed!")
        exit()


# Register a new user functions
def register_user():
    getRegistrationInput()
    validateRegistrationInput()
    encryptUserData()
    loadUserFile()


# Login user functions
def login_user():
    getAccountInfo()
    autho_user()


# Add contact functions
def addContact():
    getContactInput()
    validateContactInput()
    addContactsToFile()
    encryptContacts()


# User input functions
def help():
    print("Type 'add' to add a new contact")
    print("Type 'list' to list all online ontacts")
    print("Type 'send' to transfer file to contact")
    print("Type 'exit' to exit SecureDrop")


def broadcast_listener(s, id, online):

    ignore = 0
    try:
        while True:
            # Retrieves a broadcast
            data, addr = s.recvfrom(512)
            # Remove elements that have expired (maybe do this later)
            for element in online:
                if element[2] < int(time.time()):
                    online.remove(element)
            # Setup to ignore broacasts from ourself
            if data == id:
                ignore = addr
            # Now ignoring our own broadcasts
            if not addr == ignore:
                # Check list of online ports, if found refresh it otherwise add
                for element in online:
                    if element[1] == addr:
                        online.remove(element)
                online.append([data, addr, int(time.time())+10])
    except KeyboardInterrupt:
        pass


def broadcast_sender(port, id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        entered_hash = SHA256.new()
        entered_hash.update((email+username).encode("utf8"))
        msg = entered_hash.hexdigest()
        s.sendto(id, ('255.255.255.255', port))
        while True:
            s.sendto(msg.encode('utf-8'), ('255.255.255.255', port))
            time.sleep(5)
    except KeyboardInterrupt:
        pass


def IOManager(online):
    sys.stdin.close()
    sys.stdin = open('/dev/stdin')
    try:
        while(1):
            task = input('Securedrop > ')
            if (task == 'add'):
                addContact()
            elif(task == 'exit'):
                raise KeyboardInterrupt()
            elif(task == 'list'):
                decryptContacts()
                print(verify_online_contacts(online))
            elif(task == 'help'):
                help()
            elif(task == 'send'):
                print("Not currently available")
            else:
                print("Unknown command, type help for help.")
    except KeyboardInterrupt:
        pass


# Verify people in contacts who are online, given array of online users
def verify_online_contacts(online):
    global JSON_data
    onlineContacts = []
    # For each people, get hashed email
    for person in online:
        personEmail = person[0]
        print("Hewwo Purrson")
        for contacts in JSON_data['contacts']:
            print("contacts:\n", contacts, "\n")
            # print(contacts[0], "\n")
            # print(contacts['name'], "\n")
            contactName = contacts['name']
            contactEmail = contacts['email']
            entered_hash = SHA256.new()
            entered_hash.update((contactEmail+contactName).encode("utf8"))
            hashEmail = entered_hash.hexdigest()
            # print("Person: ", personEmail, "\nHash: ", hashEmail.encode())
            if personEmail == hashEmail.encode():
                onlineContacts.append([contactName, contactEmail, person[1]])
    return onlineContacts

def tcpManager() :
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 10000)
    sock.bind(server_address)
    sock.listen(1)

    while True:
        connection, client_address = sock.accept()
    try:
        while True:
            data = connection.recv(16)

def main():
    # Main functionality
    if account_check():
        login_user()
        print("Welcome back ", username)
    else:
        register_user()
        print("Welcome to Securedrop", username)

    online = Manager().list()
    procs = list()
    id = get_random_bytes(16)
    # listen for other broadcasts on network
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    s.bind(('', 1337))

    IOManager_worker = Process(target=IOManager, args=(online,))

    broadcast_listener_worker = Process(target=broadcast_listener, args=(s, id, online))
    broadcast_sender_worker = Process(target=broadcast_sender, args=(1337, id))
    procs.append(broadcast_listener_worker)
    procs.append(broadcast_sender_worker)
    procs.append(IOManager_worker)

    try:
        sys.stdin.close()
        for p in procs:
            p.start()
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        for p in procs:
            if p.is_alive():
                p.terminate()
                time.sleep(0.1)
            if not p.is_alive():
                p.join()


if __name__ == '__main__':
    main()
