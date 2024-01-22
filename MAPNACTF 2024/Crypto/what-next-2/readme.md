# What Next II Writeup

by xhyr

Again, in this task, we explore the realm of cryptographically secure random generators, where predicting the next output is deemed impossible. Are you ready to test your luck and skill this time?

## Initial Thoughts

We are given two files, an `output.txt` and a `what_next_ii.py` script.

```
TMP = [0, 22330693840234311255135949029444484409546667648719176405826663892267656641027, 127168478027482847709328807841325386271927515479937061237117195618823278578116, ...]
enc = 1954128229670403595826293823451515985816812578139791173172421160740653397416251058891670696398940725266238000104900728729829302299509397650740333416176077
```

```python
# what_next_ii.py

from random import *
from Crypto.Util.number import *
from flag import flag

def encrypt(msg, KEY):
	m = bytes_to_long(msg)
	c = KEY ^ m
	return c

n = 80
TMP = [getrandbits(256) * _ ** 2 for _ in range(n)]
KEY = sum([getrandbits(256 >> _) ** 2 for _ in range(8)])

enc = encrypt(flag, KEY)

print(f'TMP = {TMP}')
print(f'enc = {enc}')
```

I think this has something to do with cracking python random number generators.

In the TMP we get a total of 256 \* 80 random bits (20,480 bits) but actually there is only 20224 bits we can use because the first 256 bits cannot be retrieved since it is multiplied to 0.

Given the TMP we can get the initial bits.

```python
TMP = [tmp values]
initial_values = []
for i, t in enumerate(TMP):
  if (i == 0): continue # skip first since its useless
  initial_values.append(t // (i ** 2))
```

## WRONG TURN

Then, to use the [RandCrack](https://github.com/tna0y/Python-random-module-cracker) library. We need 624, 32 bit integers to predict the next values so we can find the key.

Since we have a total of 20,224 bits. We can have, 632, 32 bit integers.

So, now we have to extract the bits.

```python
# Extracting Bits
extracted_bits = []
for val in initial_values:
    for i in range(8):
        extracted_bits.append(val >> (256 - 32 * (i + 1)) & 0xFFFFFFFF)

print(len(extracted_bits)) # 632
```

Nope couldn't make it work. Fundamentally wrong approach, I think.

## RIGHT TURN

After trying for some time, I could not get the predictor to work with RandCrack probably because RandCrack only accepts 32 bit inputs. So, in search for another library that could help, I found this [ExtendedMT19937Predictor](https://github.com/NonupleBroken/ExtendMT19937Predictor) which was hinted to by the previous flag of the last challenge. Hayst.

```python
predictor = ExtendMT19937Predictor()

for v in initial_values[:78]:
    predictor.setrandbits(v, 256)

# check if the predictor is working using the remaining initial value
print(f"given  : {initial_values[78]}")
print(f"predict: {predictor.predict_getrandbits(256)}")
```

After confirming that we have a working predictor, we just have to generate the key similar to how the encryption script generated theirs.

```python
KEY = sum([predictor.predict_getrandbits(256 >> _) ** 2 for _ in range(8)])
```

Then, we just have to XOR the encrypted message and the key then convert it to bytes and decode.

```python
print(long_to_bytes(KEY ^ enc).decode())
```

Then, we get the flag: MAPNA{4Re_y0U_MT19937_PRNG_pr3d!cT0r_R3ven9E_4057950503c1e3992}
