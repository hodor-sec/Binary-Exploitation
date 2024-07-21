#!/usr/bin/env python
'''
Author: hodorsec
Title: stringchars_to_all_possible_asm.py
Description:
Generates a set of hex encoded strings, while displaying ALL possible combinations of the disassembled ASM code for the specific string

WARNING: do not use large payloads; 10 characters would be a large number due to complexity of ASM combinations.

'''

from capstone import *
from itertools import permutations
import binascii

somechars = b"\x01\x01\x03\x04\x06\x80"

output = [''.join(p) for p in permutations(somechars)]
output = sorted(set(output))

md = Cs(CS_ARCH_X86, CS_MODE_32)

for x in range(0, len(output)):
    print("\"\\x%s" % "\\x".join(y.encode('hex') for y in output[x]) + "\"")
    for i in md.disasm(output[x], 0):
        print("%s\t%s" % (i.mnemonic, i.op_str))
    print("\n")

