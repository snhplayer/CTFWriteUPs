#хуй знает у меня не работает

from pwn import *

context.binary = exe = ELF('chall', False)
libc = ELF('libc.so.6', False)
rop = ROP(libc)