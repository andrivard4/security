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
    global username;    global email;
    global password;    global confirm;
    has_digit = 0;    has_symbol = 0;
    has_upper = 0;    has_lower = 0;
    error = 1;
    
    while error == 1 or errormess != "":
        error = 0; errormess = "";
        print("Validating Input\n")
    
        if len(email.split("@")) != 2 :
            errormess += "Email is invalid\n"
            error = 1
        if password != confirm :
            errormess += "Passwords do not match\n"
            error = 1
        confirm = ""

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
            errormess += "Password needs 3 of the following:\n number, uppercase letter, lowercase letter, symbol\n"
            error = 1
        if(errormess == "" and error == 0) :
            print("Credentials verified, creating contact\n")
        else :
            print(errormess)
            getInput()


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
