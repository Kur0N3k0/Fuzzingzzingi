import argparse
import importlib
from utils import print_info

def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--bind", default="localhost", help="Host to bind")
    parser.add_argument("-p", "--port", type=int, default=7777, help="Port to bind")
    parser.add_argument(
        "-d",
        "--domain",
        default="*",
        help="Domain to intercept, if not set, intercept all.",
    )
    parser.add_argument(
        "-u",
        "--userpass",
        help="Username and password for proxy authentication, format: 'user:pass'",
    )
    parser.add_argument("--timeout", type=int, default=5, help="Timeout")
    parser.add_argument("--ca-key", default="./ca-key.pem", help="CA key file")
    parser.add_argument("--ca-cert", default="./ca-cert.pem", help="CA cert file")
    parser.add_argument("--cert-key", default="./cert-key.pem", help="site cert key file")
    parser.add_argument("--cert-dir", default="./certs", help="Site certs files")
    parser.add_argument(
        "--request-handler",
        help="Request handler function, example: foo.bar:handle_request",
    )
    parser.add_argument(
        "--response-handler",
        help="Response handler function, example: foo.bar:handle_response",
    )
    parser.add_argument(
        "--save-handler",
        help="Save handler function, use 'off' to turn off, example: foo.bar:handle_save",
    )
    parser.add_argument(
        "--make-certs", action="store_true", help="Create https intercept certs"
    )
    parser.add_argument(
        "--make-example",
        action="store_true",
        help="Create an intercept handlers example python file",
    )
    args = parser.parse_args()

    global request_handler, response_handler, save_handler

    if args.request_handler:
        module, func = args.request_handler.split(":")
        m = importlib.import_module(module)
        request_handler = getattr(m, func)
    else:
        request_handler = None

    if args.response_handler:
        module, func = args.response_handler.split(":")
        m = importlib.import_module(module)
        response_handler = getattr(m, func)
    else:
        response_handler = None

    if args.save_handler:
        if args.save_handler == "off":
            save_handler = None
        else:
            module, func = args.save_handler.split(":")
            m = importlib.import_module(module)
            save_handler = getattr(m, func)
    else:
        save_handler = print_info

    return args

args = parse_arguments()

# 데이터베이스 설정 추가
db_config = {
    'host': '13.209.63.65',
    'user': 'zzingzzingi',
    'password': '!Ru7eP@ssw0rD!12',
    'database': 'Fuzzingzzingi'
}
