import mysql.connector
from mysql.connector import errorcode

config = {
    'user': 'zzingzzingi',
    'password': '!Ru7eP@ssw0rD!12',
    'host': '13.209.63.65',
    'database': 'Fuzzingzzingi',
}

class Database:
    def __init__(self):
        try:
            self.conn = mysql.connector.connect(**config)
            self.cursor = self.conn.cursor()
            print("Connected to MySQL database")
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
            else:
                print(err)

    def save_packet(self, packet):
        add_packet = ("INSERT INTO requests "
                    "(url, parameters, method, protocol_version, headers, cookies, response_body) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)")
        data_packet = (packet['url'], packet['parameters'], packet['method'], packet['protocol_version'],
                    packet['headers'], packet['cookies'], packet['response_body'])
        self.cursor.execute(add_packet, data_packet)
        self.conn.commit()

    def save_collected_url(self, url):
        add_url = ("INSERT INTO collected_urls (url) "
                "VALUES (%s) ON DUPLICATE KEY UPDATE collected_at=CURRENT_TIMESTAMP()")
        self.cursor.execute(add_url, (url,))
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()
