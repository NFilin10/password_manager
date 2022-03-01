import hashlib
from database import Database
from encryption import Encryption
from app_func import AppFunctions

def main():
    try:
        user_login = input("Insert Your login\nType 1 if You are a new user\n")
        if user_login == "1":
            user_login = input("Insert Your login: ")
            master_pass = input("Insert Your master password: ")
            master_pass_repeat = input("Repeat Your master password: ")
            if master_pass == master_pass_repeat:
                master_pass_hash = hashlib.sha256(master_pass.encode())
                master_pass_hash_text = master_pass_hash.hexdigest()
                select_query = ("SELECT login FROM users WHERE login=(%s);")
                values = user_login
                database.cursor.execute(select_query, values)
                database.connection.commit()
                data = database.cursor.fetchall()
                if data == ():
                    insert_query = ("INSERT INTO users (login, password) VALUES (%s, %s);")
                    values = user_login, master_pass_hash_text
                    database.cursor.execute(insert_query, values)
                    database.connection.commit()
                    print("Your account is created")
                    main()
                else:
                    print("Login already exists")
                    main()
            else:
                print("Passwords do not match")
                main()
        else:
            master_pass = input("Insert Your master password: ")
            master_pass_hash = hashlib.sha256(master_pass.encode())
            master_pass_hash_text = master_pass_hash.hexdigest()
            functions.select_query = ("SELECT login, password FROM users WHERE login = %s AND password = %s;")
            values = user_login, master_pass_hash_text
            database.cursor.execute(functions.select_query, values)
            database.connection.commit()
            data = database.cursor.fetchall()
            if data == ():
                print("Incorrect login or password")
                main()
            else:
                while True:
                    print("1 - insert new password\n2 - print all passwords\n3 - find definite app password\n4 - find app and password by login")
                    func = input("Choose func: ")
                    if func == '1':
                        functions.insert_password(master_pass, master_pass_hash_text, user_login)

                    elif func == '2':
                       functions.show_all_passwords(master_pass_hash_text, master_pass, user_login)

                    elif func == '3':
                        functions.find_app_pass(master_pass_hash_text, master_pass, user_login)

                    elif func == '4':
                        functions.find_pass_by_login(master_pass_hash_text, master_pass, user_login)
    except Exception as e:
        database.connection.close()

database = Database()
encryption = Encryption()
functions = AppFunctions()

if __name__ == '__main__':
    main()