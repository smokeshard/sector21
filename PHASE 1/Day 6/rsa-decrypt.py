# Rivest-Shamir-Adleman Algorithm Text File Decryption Script (to be used with rsa-encrypt.py)
# Author: @smokeshard on Discord
# ======================================================================================================================

import os

def parsePrivateKey(filePrivateKey):
    with open(filePrivateKey, "r") as file:
        d, n = map(int, file.read(). split(","))
    return d, n

def decrypt(fileContent, privateKey):
    d, n = privateKey
    return " ".join([chr(pow(int(char), d, n)) for char in fileContent])
    
if __name__ == "__main__":
    filePath = input("\nInput the absolute path of encrypted file: ")
    filePrivateKey = input("Input the absolute path of private key: ")
    privateKey = parsePrivateKey(filePrivateKey)
    with open(filePath, "r") as file:
        fileContent = file.read().split()
    with open ("./rsa-decrypt.txt", "w") as file:
        file.write(decrypt(fileContent, privateKey))
    print("[SUCC] Decryption complete! Decrypted data is stored in 'rsa-decrypt.txt'.")