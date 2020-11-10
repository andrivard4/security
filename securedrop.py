from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import json
import getpass
import os
import sys

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
def getRegistrationInput() :
    #Get user input from command line
    #Save it in the above variables
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
def validateRegistrationInput() :
    global username;    global email;
    global password;    global confirm;
    has_digit = 0;    has_symbol = 0;
    has_upper = 0;    has_lower = 0;
    error = 1;        errormess = "";

    while error == 1 or errormess != "":
        errormess = ""
        error = 0
        email_contents = email.split("@")
        if len(email_contents) != 2 or email_contents[1] == "" or email_contents[1][0] == "." :
            errormess += "Email is invalid\n"
            error = 1
        elif len(email_contents[1].split(".")) != 2 or email_contents[1].split(".")[1] == ""  :
            errormess += "Email is invalid\n"
            error = 1

        # Make sure passwords match
        if password != confirm :
            errormess += "Passwords do not match\n"
            error = 1
        # get rid of data in confirm variable, no longer used
        confirm = ""

        # check length of password
        # if length is good, check to see if lower, upper, number, symbol
        #  present in the password
        if len(password) < 8 or len(password) > 100 :
            errormess += "Password needs to be 8-100 characters in length\n"
            error = 1
        else:
            for character in password:
                if character.isdigit() :
                    has_digit = 1
                if character.islower() :
                    has_lower = 1
                if character.isupper() :
                    has_upper = 1
                if not character.isalnum() and not character.isspace:
                    has_symbol = 1;
                if character.isspace() :
                    errormess += "Password cannot contain white space"
                    error = 1;
        if (has_digit + has_lower + has_upper + has_symbol) < 3 :
            errormess += "Password needs all of the following:\n number, uppercase letter, lowercase letter, symbol\n"
            error = 1

        # if any error occured, call getInput and restart the loop
        # otherwise continue
        if(errormess == "" and error == 0) :
            return
        else :
            print(errormess)
            getRegistrationInput()

# Andrew
def keyGen() :
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
def encryptUserData() :
    #Encrypts the user data
    global salt
    global encrypted_password
    global password
    salt = get_random_bytes(2)
    password_hash = SHA256.new()
    keyGen()
    password_hash.update(salt + password.encode("utf8"))
    #we no longer want the unencrypted password to exist
    password = ""
    encrypted_password = password_hash.hexdigest()

# Andrew
def loadUserFile() :
    user = open(os.path.expanduser("~") + "/.securedrop/user.log", "w")
    user.write(json.dumps({'email':email, 'name': username, 'credentials' : salt.hex() + ":" + encrypted_password, 'pub' : public_key.export_key().hex()}));
    user.close()

def account_check() :
    if os.path.exists(os.path.expanduser("~") + "/.securedrop/user.log") :
        return 1
    os.mkdir(os.path.expanduser("~") + "/.securedrop")
    return 0

# Get contact name and email
# Cassie, Pooja
def getContactInput():
    global input_name;    global input_email;
    input_name = input('Enter Contact Name:  ')
    input_email = input('Enter Contact Email:  ')


#Validate email is an email address
# Cassie, Pooja
def validateContactInput():
    global input_email;
    error = 1;

    # Make sure email has *@*.* where *s are replaced with any character
    while error == 1:
        email_contents = input_email.split("@")
        if len(email_contents) != 2 or email_contents[1] == "" or email_contents[1][0] == "." :
            print("Email is invalid\n")
        elif len(email_contents[1].split(".")) != 2 or email_contents[1].split(".")[1] == ""  :
            print("Email is invalid\n")
        else:
            error = 0;

        if error == 1:
            getContactInput();


#This one will be interesting...
#When the user creates the account, we create a public and private key with it
#The private key is then encrypted and stored in ~/.securedrop/private.pem
#That file is encrypted with a key generated by the user's password and salt
#We can assume the key is decrypted already from MS2 and stored as a global variable private_key
#Use that private key to decrypt the contact data (basically undo what was done in the encrypt portion)
#once that is done we can parse the data as a JSON file (use python's json library)
#This all only needs to be done if the file exists yet... so check that first (the file should be at ~/.securedrop/contacts.log)
#New account, new private and public key
#encrypted and stored in ~/.securedrop/private.pem
#File then encrypted with key based on password and salt
#use private key to decrypt contact data, check if file is there
#Parse data as JSON
#add contact and encrypt


#########
# TBC
########
# Cassie, Pooja
def decryptContacts():
    global JSON_data

    # Get contact file and see if it exists
    try:
        contactfile = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "rb")
    except (OSError, IOError):
        return
    if os.path.getsize( os.path.expanduser("~") + "/.securedrop/contacts.log" ) == 0:
        return

    # If contact file exists and there is contnet, decrypt
    enc_session_key, nonce, tag, ciphertext = \
        [ contactfile.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    JSON_data = json.loads(cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8'))


#Add a contact to the JSON data
# Cassie, Pooja
def addContactsToFile():
    global input_name;    global input_email;
    global JSON_data

    for email in JSON_data:
        if input_email == email:
            print("This email already exists as a contact.\n")
            return
    list = JSON_data['contacts']
    list.append({'name':input_name, 'email':input_email})
    JSON_data.update({'contacts': list})


#Encrypt the contact info with the public key then write it to the contact file
#The public key will be stored in the global variable public_key
#This works kinda like how task3 worked... Check the link I put in discord regarding that
# Cassie, Pooja
def encryptContacts():
    global input_name;    global input_email;
    global JSON_data

    if not os.path.exists(os.path.expanduser("~") + "/.securedrop"):
        os.mkdir(os.path.expanduser("~") + "/.securedrop")
    file_out = open(os.path.expanduser("~") + "/.securedrop/contacts.log", "wb")
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(JSON_data, indent=2).encode('utf-8'))
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

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
        key_file.close();
        cipher = AES.new(PBKDF2(password, bytes.fromhex(salt), dkLen=16), AES.MODE_EAX, nonce)
        private_key = RSA.import_key(cipher.decrypt_and_verify(encrypted_key,tag))
    else:
        print("Login Failed!")
        exit()

def register_user():
    getRegistrationInput()
    validateRegistrationInput()
    encryptUserData()
    loadUserFile()

def login_user():
    getAccountInfo()
    autho_user()

def addContact():
    getContactInput()
    validateContactInput()
    addContactsToFile()
    encryptContacts()

def help():
    print("Type 'add' to add a new contact")
    print("Type 'list' to list all online ontacts")
    print("Type 'send' to transfer file to contact")
    print("Type 'exit' to exit SecureDrop")

if account_check():
    login_user()
    print("Welcome back ", username)
else :
    register_user()
    print("Welcome to Securedrop", username)


while(1):
    task = input('Securedrop > ')
    if (task == 'add'):
        addContact()
    elif(task == 'exit'):
        input("Terminating Securedrop...")
        exit(1)
    elif(task == 'list'):
        decryptContacts()
        print(JSON_data['contacts'])
    elif(task == 'help'):
        help()
    elif(task == 'send'):
        print("Not currently available")
    else:
        print("Unknown command, type help for help.")
