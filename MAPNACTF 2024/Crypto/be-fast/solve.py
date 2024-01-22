#!/usr/bin/python3

from pwn import *
from binascii import *
from itertools import permutations
from Crypto.Cipher import DES

def pad(text):
    if len(text) % 8 != 0:
        text += (b'\xff' * (8 - len(text) % 8))
    return text

def decrypt(msg, key):
    des = DES.new(key, DES.MODE_ECB)
    decrypted_data = des.decrypt(msg)
    return pad(decrypted_data)

# context.log_level = 'debug'

url = "3.75.180.117"
port = "37773"

io = remote(url, port)
# io = process(['python3', 'src/be_fast.py'])

keys = [
    b'aaaaaaaa',
    b'bbbbbbbb',
    b'cccccccc',
    b'dddddddd',
    b'eeeeeeee',
    b'ffffffff',
    b'gggggggg',
    b'hhhhhhhh',
    b'iiiiiiii',
    b'jjjjjjjj',
    b'kkkkkkkk',
    b'llllllll',
    b'mmmmmmmm',
    b'nnnnnnnn',
]

for key in keys:
    io.recvuntil(b'hex: ')
    io.sendline(hexlify(key))

io.recvuntil(b'enc =')
encrypted = io.recvline().decode().strip()[2:-1]

print('ENCRYPTED: ', encrypted)

# last 7 keys
keys = [
        b'hhhhhhhh',
        b'iiiiiiii',
        b'jjjjjjjj',
        b'kkkkkkkk',
        b'llllllll',
        b'mmmmmmmm',
        b'nnnnnnnn',
    ]

perms = permutations(keys)

enc_data = unhexlify(encrypted)

for perm in perms:
    
    msg = enc_data
    for k in perm:
        msg = decrypt(msg, k)
    
    perma_key = b'nnnnnnnn'
    for i in range(14):
        msg = decrypt(msg, perma_key)
    
    if (msg.startswith(b'TOP_SECRET:')):
        print('MESSAGE:', hexlify(msg))
        io.sendline(hexlify(msg).rstrip(b'f'))
        break

io.interactive()