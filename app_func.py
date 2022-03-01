from database import Database
from encryption import Encryption

class AppFunctions(Database, Encryption):
    def __init__(self):
        super().__init__()

    def insert_password(self, master_pass, master_pass_hash_text, user_login):
        app = input("Insert app name: ")
        login = input("Insert login: ")
        password = input("ur password: ")
        ciphertext = self.encrypt(master_pass, password)
        insert_query = ("INSERT INTO passwords (app, login, password, user_name, user_passwd) VALUES  (%s, %s, %s, %s, %s);")
        values = app, login, ciphertext, user_login, master_pass_hash_text
        self.cursor.execute(insert_query, values)
        self.connection.commit()
        print("Password added")

    def show_all_passwords(self, master_pass_hash_text, master_pass, user_login):
        select_query = ("SELECT password, app, login FROM passwords WHERE user_name= %s AND user_passwd = %s;")
        values = user_login, master_pass_hash_text
        self.cursor.execute(select_query, values)
        self.connection.commit()
        data = self.cursor.fetchall()
        if data == ():
            print("No passwords")
        else:
            for datas in data:
                passwords = (datas['password'])
                app = (datas['app'])
                login = (datas['login'])
                print(str(app).capitalize() + "\n" + "Login: " + login + "\n" + "Password: " + self.decrypt(master_pass, passwords))

    def find_app_pass(self, master_pass_hash_text, master_pass, user_login):
        app_name = input("Insert app name: ")
        select_query = ("SELECT password, app, login FROM passwords WHERE user_name = %s AND user_passwd = %s AND app= %s;")
        values = user_login, master_pass_hash_text, app_name
        self.cursor.execute(select_query, values)
        self.connection.commit()
        data = self.cursor.fetchall()
        if data == ():
            print("No such app")
        else:
            for datas in data:
                passwords = (datas['password'])
                app = (datas['app'])
                login = (datas['login'])
                print(str(app).capitalize() + "\n" + "Login: " + login + "\n" + "Password: " + self.decrypt(master_pass, passwords))

    def find_pass_by_login(self, master_pass_hash_text, master_pass, user_login):
        login = input("Insert login: ")
        select_query = ("SELECT password, app, login FROM passwords WHERE user_name = %s AND user_passwd = %s AND login = %s;")
        values = user_login, master_pass_hash_text, login
        self.cursor.execute(select_query, values)
        self.connection.commit()
        data = self.cursor.fetchall()
        if data == ():
            print("No such login")
        else:
            for datas in data:
                passwords = (datas['password'])
                app = (datas['app'])
                login = (datas['login'])
                print(login + "\n" + "App: " + app + "\n" + "Password: " + self.decrypt(master_pass, passwords))