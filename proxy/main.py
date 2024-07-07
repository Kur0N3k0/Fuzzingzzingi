from proxy_server import run_server
from config import parse_arguments
from ssl_utils import make_certs, make_example

def main():
    args = parse_arguments()
    
    if args.make_certs:
        make_certs(args)
        return
    
    if args.make_example:
        make_example()
        return
    
    run_server(args)

if __name__ == "__main__":
    main()