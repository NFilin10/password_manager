import pymysql
from db_config import *

class Database():
    def __init__(self):
        try:
            self.connection = pymysql.connect(
                host=host,
                port=3306,
                user=user,
                password=password,
                database=db_name,
                cursorclass=pymysql.cursors.DictCursor
            )
            self.cursor = self.connection.cursor()
        except:
            print("error")
