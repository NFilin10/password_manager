import pymysql
from db_config import *
import hashlib
import os
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


try:
    connection = pymysql.connect(
        host=host,
        port=3306,
        user=user,
        password=password,
        database=db_name,
        cursorclass=pymysql.cursors.DictCursor
    )

except:
    print("error")

cursor = connection.cursor()

def deriveKey(passphrase, salt: bytes=None):
    if salt is None:
        salt = os.urandom(8)
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000), salt


def encrypt(passphrase, plaintext):
    key, salt = deriveKey(passphrase)
    aes = AESGCM(key)
    iv = os.urandom(12)
    plaintext = plaintext.encode("utf8")
    ciphertext = aes.encrypt(iv, plaintext, None)
    return "%s-%s-%s" % (hexlify(salt).decode("utf8"), hexlify(iv).decode("utf8"), hexlify(ciphertext).decode("utf8"))


def decrypt(passphrase, ciphertext):
    salt, iv, ciphertext = map(unhexlify, ciphertext.split("-"))
    key, _ = deriveKey(passphrase, salt)
    aes = AESGCM(key)
    plaintext = aes.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf8")

def insert_password(master_pass, master_pass_hash_text):
    app = input("Insert app name: ")
    login = input("Insert login: ")
    password = input("ur password: ")
    ciphertext = encrypt(master_pass, password)
    insert_query = ("INSERT INTO passwords (password, user, app, login) VALUES (%s, %s, %s, %s);")
    values = ciphertext, master_pass_hash_text, app, login
    cursor.execute(insert_query, values)
    connection.commit()
    print("Password added")

def show_all_passwords(master_pass_hash_text, master_pass):
    select_query = ("SELECT password, app, login FROM passwords WHERE user=(%s);")
    values = master_pass_hash_text
    cursor.execute(select_query, values)
    connection.commit()
    data = cursor.fetchall()
    if data == ():
        print("No passwords")
    else:
        for datas in data:
            passwords = (datas['password'])
            app = (datas['app'])
            login = (datas['login'])
            print(str(app).capitalize() + "\n" + "Login: " + login + "\n" + "Password: " + decrypt(master_pass, passwords))

def find_app_pass(master_pass_hash_text, master_pass):
    app_name = input("Insert app name: ")
    select_query = ("SELECT password, app, login FROM passwords WHERE user=(%s) AND app=(%s);")
    values = master_pass_hash_text, app_name
    cursor.execute(select_query, values)
    connection.commit()
    data = cursor.fetchall()
    if data == ():
        print("No such app")
    else:
        for datas in data:
            passwords = (datas['password'])
            app = (datas['app'])
            login = (datas['login'])
            print(str(app).capitalize() + "\n" + "Login: " + login + "\n" + "Password: " + decrypt(master_pass, passwords))

def find_pass_by_login(master_pass_hash_text, master_pass):
    login = input("Insert login: ")
    select_query = ("SELECT password, app, login FROM passwords WHERE user=(%s) AND login=(%s);")
    values = master_pass_hash_text, login
    cursor.execute(select_query, values)
    connection.commit()
    data = cursor.fetchall()
    if data == ():
        print("No such login")
    else:
        for datas in data:
            passwords = (datas['password'])
            app = (datas['app'])
            login = (datas['login'])
            print(login + "\n" + "App: " + app + "\n" + "Password: " + decrypt(master_pass, passwords))

def main():
    master_pass = input("Insert Your master password: ")
    master_pass_hash = hashlib.sha256(master_pass.encode())
    master_pass_hash_text = master_pass_hash.hexdigest()

    while True:
        print("1 - insert new password\n2 - print all passwords\n3 - find definite app password\n4 - find app and password by login")
        func = input("Choose func: ")
        if func == '1':
            insert_password(master_pass, master_pass_hash_text)

        elif func == '2':
           show_all_passwords(master_pass_hash_text, master_pass)

        elif func == '3':
            find_app_pass(master_pass_hash_text, master_pass)

        elif func == '4':
            find_pass_by_login(master_pass_hash_text, master_pass)

    connection.close()

main()

