# help from https://pymotw.com/2/socket/tcp.html
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
import json
import getpass
import os
import sys
import socket
import time
import threading
from base64 import b64encode, b64decode
import queue
from multiprocessing import Process, Manager, Queue


############################################################
# Class: User
####################
# Description: All Functions and Values associated with the current user who is
#                logged into securedrop
####################
# Class Values: userName, userEmail, public_key, private_key, password, salt,
#                 contacts, hash, hashed identity
####################
# Functions:
#  getContacts:     Returns contacts of user
#  addContact:      Adds contact to user.contacts given contact name and email
#  saveUserData:    Encrypt the contact info with the public key and write to
#                     the user's contact file
#  export_keys:     Define the public and private export_keys
#  import_keys:     Define the public and private import_keys
#  loadUserData:    Decrypts ~/.securedrop/contacts.log, should it exist
#  set_contact_key: Sets a contact public_key given a contact name, email, and
#                     public_key
####################
# TESTING PURPOSES ONLY
#  toPrint:      Prints properties of the user
############################################################
class User:
    def __init__(self, name, email, public, private, password, salt):
        self.name = name
        self.email = email
        self.public_key = public
        self.private_key = private
        self.hashed_password = password
        self.salt = salt
        self.contacts = []
        entered_hash = SHA256.new()
        entered_hash.update((self.email+self.name).encode("utf8"))
        self.hashed_ideneity = entered_hash.hexdigest()

    # Get contacts of the user
    def getContacts(self):
        return self.contacts

    # Add a contact to the user
    def addContact(self, name, email):
        self.contacts.append({'name': name, 'email': email, 'public_key': ''})


    # Encrypt the contact info with the public key then write it to the contact file
    def saveUserData(self):
        if not os.path.exists(os.path.expanduser("~") + "/.securedrop"):
            os.mkdir(os.path.expanduser("~") + "/.securedrop")

        file_out = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "wb")
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        user_data_json = json.dumps({'contacts': self.contacts}, indent=2)

        ciphertext, tag = cipher_aes.encrypt_and_digest(user_data_json.encode('utf-8'))
        [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        file_out.close()

    def export_keys(self):
        if self.public_key is not None:
            self.public_key = self.public_key.publickey().export_key()
        if self.private_key is not None:
            self.private_key = self.private_key.export_key()

    # Define Public and Private export keys of the user
    def import_keys(self):
        if self.public_key is not None:
            self.public_key = RSA.import_key(self.public_key)
        if self.private_key is not None:
            self.private_key = RSA.import_key(self.private_key)

    def loadUserData(self):
        # Get contact file and see if it exists
        try:
            contactfile = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "rb")
        except (OSError, IOError):
            return
        if os.path.getsize(os.path.expanduser("~") + "/.securedrop/contacts.log") == 0:
            return
        # If contact file exists and there is contnet, decrypt
        enc_session_key, nonce, tag, ciphertext = \
            [contactfile.read(x) for x in (self.private_key.size_in_bytes(), 16, 16, -1)]
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        JSON_data = json.loads(cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8'))
        self.contacts = JSON_data['contacts']

    def set_contact_key(self, name, email, key):
        for contact in self.contacts:
            if (contact['name'] == name and contact['email'] == email):
                contact['public_key'] = key
        self.import_keys()
        self.saveUserData()
        self.export_keys()

    def toPrint(self):
        print("name: ", self.name)
        print("email: ", self.email)
        print("contacts: ", self.contacts)
        print("public_key: ", self.public_key)
        print("private_key: ", self.private_key)
        print("hashed_password: ", self.hashed_password)
        print("salt: ", self.salt)


############################################################
# get_ip_address()
####################
# Description: Retrieves the current IP address program will run on
# Params: None
# Return: The IP address
############################################################
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    address = s.getsockname()
    s.close()
    return address


############################################################
# identityToContact(identity, contracts)
####################
# Description: Given a hashed email and a list of contacts, find the contact
#                associated with the identity
# Params: identity: a hashed email
#         contacts: list of user contacts
# Return: The contact, should the hashed email exist within the contacts
#         False, should the hashed email not exist within
############################################################
def ideneityToContact(identity, contacts):
    for contact in contacts:
        contactName = contact['name']
        contactEmail = contact['email']
        entered_hash = SHA256.new()
        entered_hash.update((contactEmail+contactName).encode("utf8"))
        hashEmail = entered_hash.hexdigest()
        if identity == hashEmail:
            return contact
    return False


############################################################
# getRegistrationInput()
####################
# Description: Registers a new user when a user does not already have an account
#              Prompts the user for a username, email, password,
#                password confirmation
# Params: None
# Return: JSON data containing username, email, password, password confirmation
############################################################
def getRegistrationInput():
    username = input('Enter Full Name: ')
    email = input('Enter Email: ')
    password = getpass.getpass(prompt='Enter Password: ')
    confirm = getpass.getpass(prompt='Re-enter Password: ')
    return {'name': username, 'email': email, 'password': password, 'confirm': confirm}


############################################################
# validateRegistrationInput(input)
####################
# Description: Checks if the user email is a sring in the format: *@*.*
#              Checks if the user password and confirm match
#              Checks if password is >7 or <101 characters, has a lowercase
#                letter, has an uppercase letter, has a symbol, has a number
# Params: input: JSON data containing email, password, confirm
# Return: True or False whether there's an error or not
############################################################
def validateRegistrationInput(input):
    email = input['email']
    password = input['password']
    confirm = input['confirm']
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
            return True
        else:
            print(errormess)
            return False


############################################################
# keyGen(password, salt)
####################
# Description: Generates a private_key and public_key
#              Saves the private_key to a file in securedrop
# Params: password: the user's input password
#         salt: salt used to hash the password
# Return: private_key, public_key
############################################################
def keyGen(password, salt):
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
    return (private_key, public_key)


############################################################
# encryptUserData(input)
####################
# Description: Encrypts the user's data and generates a public and private key
# Params: input: JSON data containing password
# Return: A User class value containing name, email, public_key, private_key,
#           encrypted password, salt
############################################################
def encryptUserData(input):
    # Encrypts the user data
    password = input['password']
    salt = get_random_bytes(2)
    password_hasher = SHA256.new()
    private_key, public_key = keyGen(password, salt)

    password_hasher.update(salt + password.encode("utf8"))
    encrypted_password = password_hasher.hexdigest()

    return User(input['name'], input['email'], public_key, private_key, encrypted_password, salt)


############################################################
# loadUserFile(user)
####################
# Description: Take user data and write it to the user log within securedrop
# Params: user: a User class
# Return: None
############################################################
def loadUserFile(user):
    email = user.email
    name = user.name
    salt = user.salt
    pswd = user.hashed_password
    public_key = user.public_key
    userFile = open(os.path.expanduser("~") + "/.securedrop/user.log", "w")
    userFile.write(
        json.dumps({
            'email': email,
            'name': name,
            'credentials': salt.hex() + ":" + pswd,
            'pub': public_key.export_key().hex()
        })
    )
    userFile.close()


############################################################
# account_check()
####################
# Description: Checks if an account is created, creates ~/.securedrop directory
#                if not
# Params: None
# Return: 1 or a 0 if ~/.securedrop/user.log exists or not respectively
############################################################
def account_check():
    if os.path.exists(os.path.expanduser("~") + "/.securedrop/user.log"):
        return 1
    os.mkdir(os.path.expanduser("~") + "/.securedrop")
    return 0


############################################################
# getContactInput()
####################
# Description: Get user input for a new contact name and email
# Params: None
# Return: name: name of contact
#         email: email of contact
############################################################
def getContactInput():
    name = input('Enter Contact Name:  ')
    email = input('Enter Contact Email:  ')
    return (name, email)


############################################################
# validateContactInput(inputs)
####################
# Description: Validate the email is an email address
# Params: inputs: name, email
#           name: input name
#           email: input email
# Return: True or False whether the email is in an email format or not
############################################################
def validateContactInput(inputs):
    name, email = inputs

    # Make sure email has *@*.* where *s are replaced with any character
    email_contents = email.split("@")
    if len(email_contents) != 2 or email_contents[1] == "" or email_contents[1][0] == ".":
        print("Email is invalid\n")
    elif len(email_contents[1].split(".")) != 2 or email_contents[1].split(".")[1] == "":
        print("Email is invalid\n")
    else:
        return True
    return False


############################################################
# addContactsToFile(user, inputs)
####################
# Description: Add a contact to the User JSON data if it does not already exist
# Params: user: a User class
#         inputs: input_name, input_email
#           input_name: new contact name
#           input_email: new contact email
# Return: None
############################################################
def addContactsToFile(user, inputs):
    input_name, input_email = inputs
    for email in user.getContacts():
        if input_email == email['email']:
            print("This email already exists as a contact.\n")
            return
    user.addContact(input_name, input_email)


############################################################
# getAccountInfo()
####################
# Description: Gets information about the user's account
# Params: None
# Return: A User class containing the information taken from the user's log
############################################################
def getAccountInfo():
    account_file = open(os.path.expanduser("~") + "/.securedrop/user.log", "r")
    account_data = account_file.read()
    account_file.close()
    account_data = json.loads(account_data)
    email = account_data['email']
    name = account_data['name']
    salt = account_data['credentials'].split(':')[0]
    hashed_password = account_data['credentials'].split(':')[1]
    public_key = RSA.import_key(bytes.fromhex(account_data['pub']))
    return User(name, email, public_key, None, hashed_password, salt)


############################################################
# autho_user()
####################
# Description: User login and verification
# Params: A User class
# Return: A User class from params with contact data and private key if login
#           was successful
#         An error and complete exit if login unsuccessful
############################################################
def autho_user(user):
    # Get user input
    print("Log in for account ", user.email)
    pswd_input = getpass.getpass(prompt='Enter Password: ')

    # Hash the input password
    pswd_input_hasher = SHA256.new()
    pswd_input_hasher.update(bytes.fromhex(user.salt) + pswd_input.encode("utf8"))
    pswd_input_hashed = pswd_input_hasher.hexdigest()

    # Verify user with hashed password
    if (user.hashed_password == pswd_input_hashed):
        print("Login Success!")
        key_file = open(os.path.expanduser("~") + "/.securedrop/private.pem","rb")
        nonce = key_file.read(16)
        tag = key_file.read(16)
        encrypted_key = key_file.read(-1)
        key_file.close()

        cipher = AES.new(
            PBKDF2(pswd_input,
                   bytes.fromhex(user.salt),
                   dkLen=16
                   ),
            AES.MODE_EAX,
            nonce
        )
        private_key = RSA.import_key(cipher.decrypt_and_verify(encrypted_key, tag))
        user.private_key = private_key
        user.loadUserData()
        return user
    else:
        print("Login Failed!")
        exit()


############################################################
# register_user()
####################
# Description: Add a new user to securedrop
# Params: None
# Return: A User class made from user input
############################################################
def register_user():
    input = getRegistrationInput()
    while(not validateRegistrationInput(input)):
        input = getRegistrationInput()
    user = encryptUserData(input)
    loadUserFile(user)
    return user


############################################################
# login_user()
####################
# Description: Calls autho_user function with User class from getAccountInfo()
# Params: None
# Return: A User class returned from autho_user
############################################################
def login_user():
    user = autho_user(getAccountInfo())
    return user


############################################################
# addContact(user_data)
####################
# Description: Gets input from user to add a contact
# Params: user_data
# Return: None
############################################################
def addContact(user_data):
    inputs = getContactInput()
    while not validateContactInput(inputs):
        inputs = getContactInput()
    user = user_data.get()
    addContactsToFile(user, inputs)
    user.import_keys()
    user.saveUserData()
    user.export_keys()
    user_data.put(user)


############################################################
# (online, user_data)
####################
# Description: Helper function for sending files
#              Gets the file location and an online contact to send it to
# Params: online: list of client arrays in the format
#                   client[hashed email, IP address]
#         user_data: the Queue()
# Return: None
############################################################
def sendFile(online, user_data):
    email = input('Please enter the users email:')
    online_contacts = listContacts(online, user_data)
    found = False
    for contact in online_contacts:
        if contact['email'] == email:
            found = contact
            break
    if not found:
        print("User is not online!")
        return
    file = input('Please enter the path to your file:')
    contact['file'] = file
    tcpFileClient(contact, user_data)


############################################################
# help()
####################
# Description: Print statements after user types command help
# Params: None
# Return: None
############################################################
def help():
    print("Type 'add' to add a new contact")
    print("Type 'list' to list all online ontacts")
    print("Type 'send' to transfer file to contact")
    print("Type 'key' to view your public key")
    print("Type 'reply' to answer request on another process")
    print("Type 'stop' to exit reply mode")
    print("Type 'exit' to exit SecureDrop")


############################################################
# broadcast_listener(s, id, online)
####################
# Description: Listens for online communication and ignores self broadcast
# Params: s: socket being used
#         id: User's broadcast id
#         online: List of all broadcasts
# Return: None
############################################################
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


############################################################
# broadcast_sender(port, id, user_data)
####################
# Description: Sends a broadcast with hashed name/email and IP address
# Params: port: 1338
#         id: User's broadcast id
#         user_data: the Queue()
# Return: None
############################################################
def broadcast_sender(port, id, user_data):
    user = user_data.get()
    user_data.put(user)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(id, ('255.255.255.255', port))
        while True:
            s.sendto(user.hashed_ideneity.encode('utf-8'), ('255.255.255.255', port))
            time.sleep(5)
    except KeyboardInterrupt:
        pass


############################################################
# contactHandler(requests, responses, user)
####################
# Description: Creates a tcp server for every online contact
# Params: requests: List of online contacts
#         responses: Queue responses
#         user: User data
# Return: None
############################################################
def contactHandler(requests, responses, user):
    active_requests = []
    # Create a tcp server thread for every online contact
    for request in requests:
        request_thread = threading.Thread(target=tcpListClient, args=(request, responses, user.hashed_ideneity))
        active_requests.append(request_thread)

    for trd in active_requests:
        trd.start()

    for trd in active_requests:
        trd.join()


############################################################
# listContacts(online, user_data)
####################
# Description: Finds all online contacts, checks if user has them in contacts,
#                check if they have user in contacts, add them to the list if so
# Params: online: List of all broadcasts
#         user_data: the Queue()
# Return:
############################################################
def listContacts(online, user_data):
    user = user_data.get()
    user_data.put(user)
    requests = list()
    responses = queue.Queue()
    my_online_contacts = verify_online_contacts(online, user)

    contactHandler(my_online_contacts, responses, user)

    parsed_responses = []
    while(responses.empty() is False):
        response = responses.get() # Check without removeing first!
        if response['type'] == 'contact':
            parsed_response = {'name': response['data'][0], 'email': response['data'][1], 'address': response['data'][2], 'public_key': response['data'][3]}
            parsed_responses.append(parsed_response)
    return parsed_responses


############################################################
# IOManager(online, user_data)
####################
# Description: Process to handle around 90% of the user's interaction
#              Deals with commands help, add, list, send, reply, key, exit
# Params: online: List of all broadcasts
#         user_data: the Queue()
# Return: None
############################################################
def IOManager(online, user_data):
    sys.stdin.close()
    sys.stdin = open('/dev/stdin')
    try:
        while(1):
            task = input('Securedrop > ')
            if (task == 'add'):
                addContact(user_data)
            elif(task == 'exit'):
                print("To exit at any time press Ctrl+C")
            elif(task == 'list'):
                for contact in listContacts(online, user_data):
                    print(contact['name'], "\t", contact['email'], "\t", "Verified" if contact['public_key'] else "Not verified")
            elif(task == 'help'):
                help()
            elif(task == 'send'):
                sendFile(online, user_data)
            elif(task == 'reply'):
                for line in sys.stdin:
                    if line[:-1] == 'stop':
                        sys.stdin.flush()
                        break
            elif(task == 'key'):
                print("This is your public key:")
                user = user_data.get()
                user_data.put(user)
                print(user.public_key.decode())
            else:
                print("Unknown command, type help for help.")
    except KeyboardInterrupt:
        pass


############################################################
# contactString(data)
####################
# Description: Converts an object type contact to a string
# Params: data: object type contact
# Return: String data
############################################################
def contactString(data):
    return data['name'] + " <" + data['email'] + ">"


############################################################
# verify_online_contacts(online, user)
####################
# Description: Verify people in contacts who are online, given an array of
#                online users
# Params: online: List of all broadcasts
#         user: a User class
# Return: list of onlineContacts
############################################################
def verify_online_contacts(online, user):
    onlineContacts = []
    # For each people, get hashed email
    for client in online:
        clientEmail = client[0]
        for contact in user.contacts:
            contactName = contact['name']
            contactEmail = contact['email']
            public_key = contact['public_key']
            entered_hash = SHA256.new()
            entered_hash.update((contactEmail+contactName).encode("utf8"))
            hashEmail = entered_hash.hexdigest()
            if clientEmail == hashEmail.encode():
                onlineContacts.append([contactName, contactEmail, client[1], public_key])
    return onlineContacts


############################################################
# encryptFile(filePath, rPublicKey, sPrivateKey)
####################
# Description: Takes an input file name and checks if file exists
#              If it exists, open and return encrypted data
# Params: filePath: path to file
#         rPublicKey: Recipient's public key
#         sPrivateKey: User/Sharer's private key
# Return: base64 encoded encrypted data, base64 encoded signature
############################################################
def encryptFile(filePath, rPublicKey, sPrivateKey):
    rPublicKey = RSA.importKey(rPublicKey)
    sPrivateKey = RSA.importKey(sPrivateKey)
    encryptedData = bytearray()
    # Check if file exists
    try:
        inputFile = open(filePath, "rb")
    except (OSError, IOError):
        print("File not found")
        return
    if os.path.getsize(filePath) == 0:
        print("File is empty")
        return
    # Read from file and close
    inputData = inputFile.read()
    fileName = filePath.split("/")[-1:]
    inputFile.close()

    # Generate data to send
    message = json.dumps({'name': fileName[0], 'data': b64encode(inputData).decode()}).encode()

    # Create the message signature
    h = SHA256.new(message)
    signature = pkcs1_15.new(sPrivateKey).sign(h)

    # Encrypt the message
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rPublicKey)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    [encryptedData.extend(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    return (b64encode(bytes(encryptedData)), b64encode(signature))


############################################################
# decryptFile(data, signature, sPublicKey, rPrivateKey)
####################
# Description: Decrypt data
# Params: data: Encrypted data
#         signature: signature used during encryption
#         sPublicKey: Sender's public_key
#         rPrivateKey: User/Receiver's private_key
# Return: Decrypted data
############################################################
def decryptFile(data, signature, sPublicKey, rPrivateKey):
    sPublicKey = RSA.importKey(sPublicKey)
    rPrivateKey = RSA.importKey(rPrivateKey)
    decryptedData = bytearray()

    data = b64decode(data)
    signature = b64decode(signature)

    # Decode the 4 variables made in encryption with User's Private Key
    sizeData = rPrivateKey.size_in_bytes()
    enc_session_key = data[0: sizeData]
    nonce = data[sizeData: sizeData + 16]
    tag = data[sizeData + 16: sizeData + 32]
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
    return json.loads(decryptedData.decode())


############################################################
# sendMessage(data, connection)
####################
# Description: Send a message to a given connection
#              Appends an EOF to tell the receiver when the data is done
# Params: data: Data to send
#         connection: Connection to send the data to
# Return: None
############################################################
def sendMessage(data, connection):
    data = (json.dumps(data)+'EOF').encode()
    connection.sendall(data)


############################################################
# saveFile(fileName, data)
####################
# Description: Saves a given file where the program is
# Params: fileName: name of the file
#         data: data to put in the file
# Return: None
############################################################
def saveFile(fileName, data):
    try:
        newFile = open(fileName, "wb")
    except (OSError, IOError):
        print("Unable to create file, try again...")

    newFile.write(data)
    newFile.close()


############################################################
# requestInput(message, options=False)
####################
# Description: Requests the user input from another process other than IOManager
#              Allows responses to messages
# Params: message: Message to show user for input
#         options=False: Either requests specific input from the user or stays
#           False
# Return: Response to options input
############################################################
def requestInput(message, options=False):
    print("You have a pending request on another process, type 'reply' to be able to respond to it.")
    sys.stdin.close()
    sys.stdin = open('/dev/stdin')
    listen = False
    return_val = ""
    while True:
        if listen:
            response = input(message)
            if response == 'stop':
                if return_val != '':
                    break
                listen = False
                continue
            found = False
            if options:
                for item in options:
                    if response == item:
                        found = True
            if found or not options:
                message = ''
                return_val = response
                print("Request complete, please type 'stop' to switch back to main process.")
            else:
                print("Invalid input, try again.")
        else:
            counter = 0
            for line in sys.stdin:
                counter += 1
                if line[:-1] == 'reply':
                    sys.stdin.flush()
                    listen = True
                    break
                elif counter == 5:
                    print("You still have a pending request on another process, type 'reply' to be able to respond to it.")
                    counter = 0
    sys.stdin.close()
    return return_val


############################################################
# tcpServer(server_address, user_data)
####################
# Description: Handles requests to user
#              Some request require authentication while others don't
# Params: server_address: IP address
#         user_data: the Queue()
# Return: None
############################################################
def tcpServer(server_address, user_data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((server_address[0], 10000))
    sock.listen(1)
    try:
        while True:
            connection, client_address = sock.accept()
            data = bytearray()
            # Receive the data in small chunks and retransmit it
            while True:
                packet = connection.recv(1240)
                if packet[-3:].decode() == 'EOF':
                    data.extend(packet[:-3])

                    break
                data.extend(packet)
            data = json.loads(data.decode())
            try:
                # If there is an identity field, parse it
                if 'identity' in data:
                    user = user_data.get()
                    user_data.put(user)
                    contact = ideneityToContact(data['identity'], user.contacts)
                    if contact:
                        data['identity'] = contact
                    else:
                        data['identity'] = False
                if (data['type'] == 'contact'):
                    # Send them back our identity
                    if not data['identity']:
                        response = {'type': 'error', 'data': 'Verified identity required for this action.'}
                        sendMessage(response, connection)
                    else:
                        response = {'type': 'contact', 'data': user.hashed_ideneity}
                        sendMessage(response, connection)
                elif data['type'] == 'file':
                    if not data['identity']:
                        response = {'type': 'error', 'data': 'Verified identity required for this action.'}
                        sendMessage(response, connection)
                    if not data['identity']['public_key']:
                        print('User', contactString(data['identity']), 'has sent you a key, please verify this is correct over a secure connection:')
                        print(data['key'])
                        print("If this is correct, accept connection to send your key and save their, otherwise refuese connection")
                        message = requestInput('Do you want to save the above key? [Y/n]', ['Y', 'n'])
                        if message == 'n':
                            sendMessage({'type': 'error', 'data': 'key rejected, communication terminated.'}, connection)
                            print('request denied!')
                            connection.close()
                            continue
                        elif message == 'Y':
                            contact = data['identity']
                            contact['public_key'] = data['key']
                            user = user_data.get()
                            user.set_contact_key(contact['name'], contact['email'], data['key'])
                            user_data.put(user)
                            print("Key has been saved!")
                    message = requestInput(contactString(data['identity']) + ' wants to send you a file, do you accept? [Y/n]', ['Y', 'n'])
                    if message == 'n':
                        sendMessage({'type': 'error', 'data': 'file rejected, communication terminated.'}, connection)
                        print('request denied!')
                    elif message == 'Y':
                        file = decryptFile(data['data'].encode(), data['signature'].encode(), data['identity']['public_key'], user.private_key)
                        saveFile(file['name'], b64decode(file['data']))
                        sendMessage({'type': 'success', 'data': 'File transfer complete!'}, connection)
                        print("File has been saved!")
                elif data['type'] == 'test':
                    # This is a simple test request, it sends messages to eachother
                    print('Test request recieved with data:', data['data'])
                    message = requestInput('What should you send back?')
                    sendMessage({'type': 'test', 'data': message}, connection)
                elif data['type'] == 'key':
                    # Handles a request when someone sends you a key. If identity isnt set, reject
                    if not data['identity']:
                        response = {'type': 'error', 'data': 'Verified identity required for this action.'}
                        sendMessage(response, connection)
                    else:
                        print('User', contactString(data['identity']), 'has sent you a key, please verify this is correct over a secure connection:')
                        print(data['data'])
                        print("If this is correct, accept connection to send your key and save their, otherwise refuese connection")
                        message = requestInput('Do you want to save the above key? [Y/n]', ['Y', 'n'])
                        if message == 'n':
                            sendMessage({'type': 'error', 'data': 'key rejected, communication terminated.'}, connection)
                            print('request denied!')
                        elif message == 'Y':
                            contact = data['identity']
                            contact['public_key'] = data['data']
                            user = user_data.get()
                            user.set_contact_key(contact['name'], contact['email'], data['data'])
                            user_data.put(user)
                            sendMessage({'type': 'success', 'data': 'key accepted and saved!'}, connection)
                            print("Key has been saved!")
                elif data['type'] == 'key-request':
                    # Handles a request when someone sends you a key. If identity isnt set, reject
                    if not data['identity']:
                        response = {'type': 'error', 'data': 'Verified identity required for this action.'}
                        sendMessage(response, connection)
                    else:
                        print('User', contactString(data['identity']), 'has requested your public key, please verify that this request is expected:')
                        message = requestInput('Do you want to send your public key? [Y/n]', ['Y', 'n'])
                        if message == 'n':
                            sendMessage({'type': 'error', 'data': 'request rejected, communication terminated.'}, connection)
                            print('request denied!')
                        elif message == 'Y':
                            sendMessage({'type': 'key', 'identity': user.hashed_ideneity, 'data': user.public_key.decode()}, connection)
                            print("Key sent!")
                else:
                    response = {'type': 'error', 'data': 'unknown type sent.'}
                    sendMessage(response, connection)
            except Exception as e:
                print("An error has been handled in the TCP server.")
                print("Error", e)
            finally:
                # Clean up the connection
                connection.close()
    except KeyboardInterrupt:
        print("Closing TCP server...")
        sock.close()
        pass


############################################################
# tcpListClient(request, responses, identityV)
####################
# Description: Check if responder is within user contacts
# Params: requests: List of online contacts
#         responses: Queue responses
#         identityV: Hashed identity of user
# Return: None
############################################################
def tcpListClient(request, responses, identityV):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((request[2][0], 10000))
    response = bytearray()
    try:
        data = {'type': 'contact', 'identity': identityV}
        sendMessage(data, sock)
        # Look for the response
        while True:
            packet = sock.recv(64)
            if packet[-3:].decode() == 'EOF':
                response.extend(packet[:-3])
                break
            response.extend(packet)
    except Exception as e:
        print("Error occured:", e)
    finally:
        # Check if the responder is within the user's contacts
        response = json.loads(response.decode())
        if (response['type'] == 'contact'):
            response['data'] = request
            responses.put(response)
        elif (response['type'] == 'error'):
            print("Error with response: ", response['data'])
        else:
            print("Error understanding response")
        sock.close()


############################################################
# tcpFileClient(request, user_data)
####################
# Description: Handle creating requests for key and file transfer
# Params: request: contact that includes a value for file path
#         user_data: the Queue()
# Return: None
############################################################
def tcpFileClient(request, user_data):
    user = user_data.get()
    user_data.put(user)
    # We are looping because one request might request a key, and then send the file
    while True:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((request['address'][0], 10000))
        response = bytearray()
        try:
            # Request a key if you dont have it, otherwise send the file
            if not request['public_key']:
                data = {'type': 'key-request', 'identity': user.hashed_ideneity}
                sendMessage(data, sock)
                print("Waiting for users response...")
            else:
                # open and encrypt the file
                file = request['file']
                file, signature = encryptFile(file, request['public_key'], user.private_key)

                # send the file, your key (used if they dont have it),
                #  and the sinature
                data = {'type': 'file', 'identity': user.hashed_ideneity, 'key': user.public_key.decode(), 'data': file.decode(), 'signature': signature.decode()}
                print("transfering file...")
                sendMessage(data, sock)

            # Look for the response
            while True:
                packet = sock.recv(64)
                if packet[-3:].decode() == 'EOF':
                    response.extend(packet[:-3])
                    break
                response.extend(packet)

        except Exception as e:
            print(e)
        finally:
            # Response handling
            response = json.loads(response.decode())
            # When an error response is retrieved, we just print the info
            if (response['type'] == 'error'):
                print("Error:", response['data'])
                break
            # When a success response is retrieved, we just print the info
            elif response['type'] == 'success':
                print(response['data'])
                break
            # Verify that the key is correct
            elif response['type'] == 'key':
                contact = ideneityToContact(response['identity'], user.contacts)
                if not contact:
                    print("Got a key from an unknown contact... ignoring")
                else:
                    print('User', contactString(contact), 'has sent you a key, please verify this is correct over a secure connection:')
                    print(response['data'])
                    print("If this is correct, accept connection to save their key, otherwise refuese request")
                    message = input('Do you want to save the above key? [Y/n]')
                    if message == 'Y':
                        contact['public_key'] = response['data']
                        user = user_data.get()
                        user.set_contact_key(contact['name'], contact['email'], response['data'])
                        user_data.put(user)
                        request['public_key']  = response['data']
                        print('Public key saved successfully!')
                    else:
                        print('request denied!')
                        break
            # This is to test TCP and we left it here for fun. It just sends an
            #  unencrypted message back and forth
            elif response['type'] == 'test':
                print('Recieved test back with data:', response['data'])
                break
            else:
                print("Error understanding response")
                break
        sock.close()



############################################################
# main()
####################
# Description: Main functionality of the program
#              Checks if the user needs to login or register
#              Get IP address, sets up broadcast listen and sender processes,
#               IO manager process, tcp process and start them
# Params: None
# Return: None
############################################################
def main():
    user = None
    # Check if user needs to login or register
    if account_check():
        user = login_user()
        print("Welcome back ", user.name)
    else:
        user = register_user()
        print("Welcome to Securedrop", user.name)

    # Gets the IP address the program will run on
    address = get_ip_address()
    procs = list()

    # This is for shared data between the processes
    # Online is populated by broadcast_listener, and read by other processes
    online = Manager().list()
    # The user will be in here, when needed it will be removed and other
    #  processes will block until its placed back in
    user_data = Queue()
    # This is genereated to ignore our own broadcasts
    id = get_random_bytes(16)
    # listen for other broadcasts on network
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(('', 1338))

    # This translates the user keys to bytearrays so its pickleable (only for
    #  cross process communication)
    user.export_keys()
    user_data.put(user)

    # Creating our processes
    IOManager_worker = Process(target=IOManager, args=(online, user_data,))
    TPCServer_manager = Process(target=tcpServer, args=(address, user_data,))
    broadcast_listener_worker = Process(target=broadcast_listener, args=(s, id, online,))
    broadcast_sender_worker = Process(target=broadcast_sender, args=(1338, id,  user_data,))

    # Populating process array
    procs.append(broadcast_listener_worker)
    procs.append(broadcast_sender_worker)
    procs.append(IOManager_worker)
    procs.append(TPCServer_manager)

    # Starts all our processes
    try:
        sys.stdin.close()
        for p in procs:
            p.start()
        while True:
            time.sleep(1)

    # Handles safely ending processes
    except KeyboardInterrupt:
        for p in procs:
            if p.is_alive():
                p.terminate()
                time.sleep(0.1)
            if not p.is_alive():
                p.join()


if __name__ == '__main__':
    main()
