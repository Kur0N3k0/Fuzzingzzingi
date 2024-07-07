import socket
import ssl
import threading
from proxy_server import run_server
from config import args

# 프록시 서버 시작
if __name__ == '__main__':
    run_server(args)
