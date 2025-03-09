# Rivest-Shamir-Adleman Algorithm Text File Encryption Script (to be used with rsa-decrypt.py)
# Author: @smokeshard on Discord
# ======================================================================================================================

import os
import random

def modulusInverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return None

def highestCommonFactor(e, phi):
    while phi:
        e, phi = phi, e % phi
    return e

def checkPrime(randomNumber):
    if randomNumber < 2:
        return False
    for i in range(2, int(randomNumber ** 0.5) + 1):
        if randomNumber % i == 0:
            return False
    return True

def generatePrime():
    while True:
        randomNumber = random.randint(128, 512)
        if checkPrime(randomNumber):
            return randomNumber

def generateKeys():
    p = generatePrime()
    q = generatePrime()
    while q == p:
        q = generatePrime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while highestCommonFactor(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = modulusInverse(e, phi)
    return (e, n), (d, n)

def encrypt(fileContent, publicKey):
    e, n = publicKey
    return [pow(ord(char), e, n) for char in fileContent]

def saveKeys(publicKey, privateKey):
    with open("./Public Key.txt", "w") as pub:
        pub.write(f"{publicKey[0]}, {publicKey[1]}")
    with open("./Private Key.txt", "w") as pri:
        pri.write(f"{privateKey[0]}, {privateKey[1]}")

if __name__ == "__main__":
    publicKey, privateKey = generateKeys()
    saveKeys(publicKey, privateKey)
    fileInput = input("\nInput the absolute path of plaintext file: ")
    if not os.path.exists(fileInput):
        print(f"[ERR.] '{fileInput}' does not exist.")
    elif not os.path.isfile(fileInput):
        print(f"[ERR.] '{fileInput}' is not a valid file.")
    else:
        fileOutput = "./rsa-encrypt.txt"
        with open(fileInput, "r") as file:
            fileContent = file.read()
        with open(fileOutput, "w") as file:
            file.write(" ".join(map(str, encrypt(fileContent, publicKey))))
        print("[SUCC] Encryption complete! Encrypted data is stored in 'rsa-encrypt.txt'.")