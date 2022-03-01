from Crypto.Cipher import AES
import hashlib
import os
from binascii import hexlify, unhexlify

class Encryption():
    def __init__(self):
        pass

    def deriveKey(self, passphrase):
        salt = os.urandom(8)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 100000)
        return key, salt

    def encrypt(self, passphrase, plaintext):
        key, salt = self.deriveKey(passphrase)
        iv = os.urandom(12)
        aes = AES.new(key, AES.MODE_GCM, iv)
        plaintext = plaintext.encode("utf8")
        ciphertext = aes.encrypt(plaintext)
        return hexlify(salt) + hexlify(iv) + hexlify(ciphertext)

    def decrypt(self, passphrase, ciphertext):
        salt = ciphertext[:16]
        iv = ciphertext[16:40]
        iv = unhexlify(iv)
        ciphertext = ciphertext[40:]
        ciphertext = unhexlify(ciphertext)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), unhexlify(salt), 100000)
        aes = AES.new(key, AES.MODE_GCM, iv)
        plaintext = aes.decrypt(ciphertext)
        return plaintext.decode('utf-8')