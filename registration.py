#remember to install https://pypi.org/project/pycryptodome/
from Crypto.Hash import SHA256

username = "usr"
email = "email"
password = "pswd"
confirm = "conf"

#Pooja
def getInput() :
    #Get user input from command line
    #Save it in the above variables
    print("getInput")

#Cassie
def validateInput() :
    #validates the input
    # ex email is an email, password match...
    print("validateInput")

# Andrew
def encryptData() :
    #Andrew encrypts the user data
    hash = SHA256.new()
    hash.update('message')
    print(hash.hexdigest())

#Abhi
def loadFile() :
    #Creates a file and saves the user data
    print("loadFile")
