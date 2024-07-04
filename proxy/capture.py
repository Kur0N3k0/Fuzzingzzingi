import logging
import json
from mitmproxy import http
import mysql.connector
from mysql.connector import errorcode
from urllib.parse import urlparse, parse_qs
import time

# MySQL 연결 설정
config = {
    'user': 'zzingzzingi',  # MySQL 사용자명
    'password': '!Ru7eP@ssw0rD!12',  # MySQL 비밀번호
    'host': '13.209.63.65',  # MySQL 서버 호스트
    'database': 'Fuzzingzzingi',  # 데이터베이스 이름
}

# 데이터베이스 연결 및 테이블 설정
class Database:
    def __init__(self):
        try:
            self.conn = mysql.connector.connect(**config)
            self.cursor = self.conn.cursor()
            logging.info("Connected to MySQL database")
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                logging.error("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                logging.error("Database does not exist")
            else:
                logging.error(err)

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

# Mitmproxy addon
class CaptureAddon:
    def __init__(self):
        self.db = Database()
        self.response_data = {}

    def request(self, flow: http.HTTPFlow) -> None:
        # Initialize storage for this flow
        self.response_data[flow.id] = b""
        logging.info(f"Captured request to: {flow.request.url}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Collect the response data
        self.response_data[flow.id] += flow.response.content
        logging.info(f"Captured response from: {flow.request.url}")

    def done(self):
        # Save collected data to the database
        for flow_id, data in self.response_data.items():
            flow = self.get_flow(flow_id)
            if flow:
                url_components = urlparse(flow.request.url)
                parameters = parse_qs(url_components.query)
                packet = {
                    'url': flow.request.url,
                    'parameters': json.dumps(parameters),
                    'method': flow.request.method,
                    'protocol_version': flow.request.http_version,
                    'headers': json.dumps(dict(flow.request.headers)),
                    'cookies': json.dumps(dict(flow.request.cookies)),
                    'response_body': data.decode('utf-8', errors='replace')
                }
                self.db.save_packet(packet)
                self.db.save_collected_url(flow.request.url)
        self.db.close()
        logging.info("Saved all packets to the database.")

    def get_flow(self, flow_id):
        # This is a helper method to find the flow by ID
        for f in flow.context.flows:
            if f.id == flow_id:
                return f
        return None

addons = [
    CaptureAddon()
]
