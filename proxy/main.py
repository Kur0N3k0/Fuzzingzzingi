import argparse
import logging
from server import CustomThreadingHTTPServer
from proxy_handler import CustomProxyRequestHandler
from cert_manager import generate_certs

if __name__ == "__main__":
    # 로깅 설정을 DEBUG 레벨로 변경
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="Host to bind")
    parser.add_argument("-p", "--port", type=int, default=7777, help="Port to bind")
    parser.add_argument("-d", "--domain", default="*", help="Domain to intercept, if not set, intercept all.")
    parser.add_argument("--cert-dir", default="certs", help="Directory for certificates")
    parser.add_argument("--make-certs", action='store_true', help="Generate certificates and exit")
    args = parser.parse_args()

    if args.make_certs:
        generate_certs(args.cert_dir, args.domain)
        exit(0)

    class CustomHTTPServer(CustomThreadingHTTPServer):
        def __init__(self, server_address, RequestHandlerClass):
            super().__init__(server_address, RequestHandlerClass)
            self.args = args

    def handler(*handler_args, **handler_kwargs):
        CustomProxyRequestHandler(*handler_args, server_args=args, **handler_kwargs)

    try:
        httpd = CustomHTTPServer((args.bind, args.port), handler)
        logging.info(f"Serving HTTP on {args.bind} port {args.port} (http://{args.bind}:{args.port}/) ...")
        logging.info(f"Intercepting domain: {args.domain}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, shutting down the server")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        if 'httpd' in locals():
            httpd.server_close()
        logging.info("Server shut down")