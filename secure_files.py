
import os
import sys


# Takes an input file name and checks if file exists
# If so, open and return encrypted data
def getFileInput(inputFileName):
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
    print(inputData.decode('utf 8'))

    # similar to saveUserData


def decryptData(data):
    # similar to loadUserData
    return





# main function
getFileInput("temp.txt")
