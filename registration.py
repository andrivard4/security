#remember to install https://pypi.org/project/pycryptodome/
#to install for python3 use pip3
from Crypto.Hash import SHA256
from Crypto.Random import random
import getpass

username = "usr"
email = "email"
encrypted_password = ""
salt = 0
password = "Password"
confirm = "conf"

#Pooja
def getInput() :
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

#Cassie
def validateInput() :
    #once passwords are confirmed set confirm = "" because we no longer want it in memory ~Andrew
    #validates the input
    # ex email is an email, password match...
    print("validateInput")

# Andrew
def encryptData() :
    #Encrypts the user data
    global salt
    global encrypted_password
    global password
    salt = random.getrandbits(16)
    password_hash = SHA256.new()
    def update() :
        password_hash.update(salt + password)
    #we no longer want the unencrypted password to exist
    password = ""
    encrypted_password = password_hash.hexdigest()

#Abhi
def loadFile() :
    #Creates a file and saves the user data
    #Ignore the password and conf and save encrypted_password instead ~Andrew
    print("loadFile")

getInput()
validateInput()
encryptData()
loadFile()
print(username + ":" + email + ":" + str(salt) + ":" + encrypted_password)
