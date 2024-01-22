The analysis of the given challenge source gives us

```
def main():
	border = "+"
	pr(border*72)
	pr(border, ".::        Hi all, you should be fast, I mean super fact!!       ::.", border)
	pr(border, "You should send twenty 8-byte keys to encrypt the secret message and", border)
	pr(border, "just decrypt the ciphertext to get the flag, Are you ready to start?", border)
	pr(border*72)

	secret_msg = b'TOP_SECRET:' + os.urandom(40)            # <--- Known plaintext, enough to fill the first block (8 bytes)
	
	cnt, STEP, KEYS = 0, 14, []             # <--- Even though the banner says to provide 20 keys, we only need 14 
	md = 1

	while True:
		pr(border, "please send your key as hex: ")
		alarm(md + 1)
		ans = sc().decode().strip()
		alarm(0)
		try:
			key = unhexlify(ans)
			if len(key) == 8 and key not in KEYS:
				KEYS += [key]
				cnt += 1
			else:
				die(border, 'Kidding me!? Bye!!')
		except:
			die(border, 'Your key is not valid! Bye!!')
		if len(KEYS) == STEP:
			print(KEYS)
			HKEY = KEYS[:7]			            # The first seven keys - not used for encryption ... only as a counter
			shuffle(HKEY)			
			NKEY = KEYS[-7:]                    # The last seven keys are shuffled.
			shuffle(NKEY)
			for h in HKEY: NKEY = [key, shift(key, 1)] + NKEY       # key = last (14th) key .. this key is shifted (rotated) 7 times

            # the final key array is [14 rotated version of the last key] + shuffled permutation of the last 7 keys                
			enc = encrypt(secret_msg, NKEY[0])
			for key in NKEY[1:]:
				enc = encrypt(enc, key)
			pr(border, f'enc = {hexlify(enc)}')
			pr(border, f'Can you guess the secret message? ')
			alarm(md + 1)                   # we get 2 seconds to decrypt the secret message and send it over 
			msg = sc().strip()
			alarm(0)
			if msg == hexlify(secret_msg):
				die(border, f'Congrats, you deserve the flag: {flag}')
			else:
				die(border, f'Sorry, your input is incorrect! Bye!!')

```

So, our approach to solve the problem would be :

1. We need to provide 14 8-byte keys.
2. The first 7 keys don’t matter as they are not used in the encryption step
3. The last 7 keys are shuffled in some random order. Permutations(7,7) = 5040 possibilities.
4. The last key is rotated/shifted for 14 rounds.
5. We can pick the last key so that the rotation/shifts shouldn’t matter. I chose all ones : 1111111111111111
6. The encryption order is : 14 * [last_key] + [a permutation of the last seven keys]
7. We can take the first block b'TOP_SECR' and run it through all possible permutations and store the resulting mapping for a reverse lookup
8. We then connect to the server, send the keys and get the encrypted message back.
9. Use the first 8 bytes to lookup the appropriate permutation used on the server.
10. Reverse the encryption function in the opposite order. Reverse of the permutation order + 14 rounds with the [last_key]
11. Send the resulting message to the server and receive the flag. You can confirm that the message indeed has the known header TOP_SECRET:

```
from pwn import * 
from itertools import permutations
from Crypto.Cipher import DES

context.log_level = 'error'
keys = [
    b'1000000000000011', b'1000000000000012', b'1000000000000013', b'1000000000000014', b'1000000000000015', b'1000000000000016', b'1000000000000017',
    b'1000000000000018', b'1000000000000019', b'100000000000001a', b'100000000000001b', b'100000000000001c', b'100000000000001d', b'1111111111111111',
]

secret_block = b'TOP_SECR'      # first block of the message
signatures = {}
static_enc = b''
static_key = unhex(keys[-1])

def encrypt(msg, key):
	# msg = pad(msg)
	assert len(msg) % 8 == 0
	assert len(key) == 8
	des = DES.new(key, DES.MODE_ECB)
	enc = des.encrypt(msg)
	return enc

def decrypt(cipher, key):
     des = DES.new(key, DES.MODE_ECB)
     msg = des.decrypt(cipher)
     return msg

perms = list(permutations(keys[7:], 7))
print(f"Permutations: {len(perms)}   {perms[0]}")
enc = secret_block
for i in range(14):
    enc = encrypt(enc, static_key)
static_enc = enc

for l in perms:
    enc = static_enc
    binary_keys = []
    for k in l: 
        binary_k = unhex(k)
        enc = encrypt(enc, binary_k)
        binary_keys.append(binary_k)
    signatures[enc] = binary_keys

# R = process(["python3", "be_fast.py"])
R = remote('3.75.180.117',37773)
R.recvuntil(b'ready to start?')
R.recvline()

for i in range(14):
    R.recvuntil(b'key as hex:')
    R.sendline(keys[i])
R.recvuntil(b'+ enc = ')
enc = R.recvline().decode()
enc = bytes(enc, 'utf-8').decode().split("'")[1]
print(">>>>", enc)
enc_bytes = unhex(enc)

# get the correct permutation of the 7 keys used by the server
NKEYS = signatures[enc_bytes[:8]]
message = enc_bytes

# decrypt in the reverse order of encryption
for k in NKEYS[::-1]:
     print(k)
     message = decrypt(message, k)
# finally use the static key that does not change
for i in range(14):
     message = decrypt(message, static_key)

# The final message must start with b'TOP_SECRET:'
print(f"Final message: {message}")
R.recvuntil(b'guess the secret message?')
R.sendline(enhex(message).strip('ff'))      # strip the padding characters 
R.interactive()        # MAPNA{DES_h4s_A_f3W_5pec1f!c_kEys_7eRm3d_we4K_k3Ys_And_Sem1-wE4k_KeY5!}

```