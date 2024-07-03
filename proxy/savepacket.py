import json
import mysql.connector
import logging

# 로깅 설정
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# MySQL 연결 설정
config = {
    'user': 'zzingzzingi',  # MySQL 사용자명
    'password': '!Ru7eP@ssw0rD!12',  # MySQL 비밀번호
    'host': '13.209.63.65',  # MySQL 서버 호스트
    'database': 'Fuzzingzzingi',  # 데이터베이스 이름
}

# DB 연결 테스트
def test_db_connection():
    try:
        connection = mysql.connector.connect(**config)
        if connection.is_connected():
            logging.info("Database connection successful")
        connection.close()
    except mysql.connector.Error as err:
        logging.error(f"Database connection error: {err}")

# JSON 데이터를 검증하는 함수
def validate_json(data):
    try:
        json.dumps(data)
        return True
    except ValueError as e:
        logging.error(f"Invalid JSON data: {data} - Error: {e}")
        return False

# DB에 패킷 데이터 저장
def save_packet_to_db(packet_storage):
    logging.debug(f"Received packet_storage: {packet_storage}")
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        logging.debug("Database connection established for saving packets")

        insert_query = """
            INSERT INTO requests (url, parameters, method, protocol_version, headers, cookies, response_body)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        for packet in packet_storage:
            logging.debug(f"Processing packet: {packet}")
            parameters = json.dumps(packet.get('parameters', {}))
            headers = json.dumps(packet.get('headers', {}))
            cookies = json.dumps(packet.get('cookies', {}))

            if not validate_json(parameters) or not validate_json(headers) or not validate_json(cookies):
                logging.warning("Skipping packet due to invalid JSON")
                continue

            try:
                cursor.execute(insert_query, (
                    packet['url'],
                    parameters,
                    packet['method'],
                    packet['protocol_version'],
                    headers,
                    cookies,
                    packet['response_body']
                ))
                logging.debug(f"Successfully inserted packet: {packet['url']}")
            except Exception as e:
                logging.error(f"Error inserting packet: {e}", exc_info=True)

        connection.commit()
        logging.debug("Database commit successful")

    except mysql.connector.Error as err:
        logging.error(f"Database Error: {err}", exc_info=True)
    except Exception as e:
        logging.error(f"Unexpected Error in save_packet_to_db: {e}", exc_info=True)
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
        logging.debug("Database connection closed")

    logging.debug("Finished attempting to save packets")

# 테스트
if __name__ == "__main__":
    test_db_connection()
