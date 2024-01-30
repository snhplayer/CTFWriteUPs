
### Flip (87 solves) and Flip v2 (13 solves)

#### Description:

-   Author: ndh
    

-   flip
    
    -   You are allowed to inject a software fault.
        
    
    -   Server: `nc 139.162.24.230 31339`
        
    

-   flip v2
    
    -   Changing in main() is not allowed.
        
    
    -   Server: `nc 139.162.24.230 31340`
        
    

#### 

Solution:

The way main.py works is it loads the "encrypt" binary into memory and allows the user to modify the plaintext as well as flip a specific bit in the binary.
```c
// encrypt.c
#include "tiny-AES-c/aes.h"
#include <unistd.h>

uint8_t plaintext[16] = {0x20, 0x24};
uint8_t key[16] = {0x20, 0x24};

int main() {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, plaintext);
    write(STDOUT_FILENO, plaintext, 16);
    return 0;
}
```
```python
# main.py excerpt

# Please ensure that you solved the challenge properly at the local.
# If things do not run smoothly, you generally won't be allowed to make another attempt.
from secret.network_util import check_client, ban_client

import sys
import os
import subprocess
import tempfile

OFFSET_PLAINTEXT = 0x4010
OFFSET_KEY = 0x4020

def main():
    if not check_client():
        return

    key = os.urandom(16)
    with open("encrypt", "rb") as f:
        content = bytearray(f.read())

    # input format: hex(plaintext) i j
    try:
        plaintext_hex, i_str, j_str = input().split()
        pt = bytes.fromhex(plaintext_hex)
        assert len(pt) == 16
        i = int(i_str)
        assert 0 <= i < len(content)
        j = int(j_str)
        assert 0 <= j < 8
    except Exception as err:
        print(err, file=sys.stderr)
        ban_client()
        return

    # update key, plaintext, and inject the fault
    content[OFFSET_KEY:OFFSET_KEY + 16] = key
    content[OFFSET_PLAINTEXT:OFFSET_PLAINTEXT + 16] = pt
    content[i] ^= (1 << j)
...
```
The offsets at the top of main.py correspond to the location in memory for plaintext and key in the binary. When reading the input from the user, the pt is checked to be 16 bytes, i needs to be within the bound of the binary (21032 bytes), and j needs to select a bit from 0-7. The goal is to determine what plaintext and bit to flip to be able to determine the randomized key based on a single program output.

When I went to brute force what would happen to the binary when I flipped each bit and to check if perhaps it may just output the key directly, I ended up solving both flip and flip v2. I'm not entirely sure why there not more solves for this since I spent way longer on the other challenges. The following is the full script I used to brute force each bit flip output.
```python
import sys
import os
import subprocess
import tempfile
import binascii

OFFSET_PLAINTEXT = 0x4010
OFFSET_KEY = 0x4020
pt = bytes.fromhex("00000000000000000000000000000000")

def main():
    key = os.urandom(16)
   
    for i in range(21032):
        print(i)
        for j in range(8):
            with open("encrypt", "rb") as f:
                content = bytearray(f.read())

            # update key, plaintext, and inject the fault
            content[OFFSET_KEY:OFFSET_KEY + 16] = key
            content[OFFSET_PLAINTEXT:OFFSET_PLAINTEXT + 16] = pt
            content[i] ^= (1 << j)

            tmpfile = tempfile.NamedTemporaryFile(delete=True)
            with open(tmpfile.name, "wb") as f:
                f.write(content)
            os.chmod(tmpfile.name, 0o775)
            tmpfile.file.close()

            # execute the modified binary
            try:
                ciphertext = subprocess.check_output(tmpfile.name, timeout=0.001)
                if binascii.hexlify(ciphertext) == binascii.hexlify(key):
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
                    print("Match found!", binascii.hexlify(ciphertext), binascii.hexlify(key), i, j)
            except:
                pass
main()
```
Because this checks around 100 byte positions every couple seconds, I added many print statements so I would notice when a match was found. The timeout could probably be even lower to solve it quicker, but this solves both challenges in a minute or two. The first three solutions it finds are (byte=4545, bit=4), (byte=4551, bit=5), and (byte=5463, bit=1). I cancelled it soon after finding the third solution so there may be more.

Now the hard part: testing locally to make sure we don't get banned. Refer to the main.py snippet at the top, any exception hit causes ban_client(), which would be a shame after solving the challenge. Here are the docker commands to build and test locally.
```
docker build -t flip .
docker run -p 31339:31339 --name flip flip
# Also some useful commands for cleanup
docker ps --all # List all containers
docker stop flip # Stop the named container
docker rm flip # Delete the named container
docker image ls # List all downloaded images
docker rmi flip # Delete the named image
docker rmi <IMGID> # Delete those unnamed images
```
You can then nc to localhost 31339, and input the pt (16 bytes of 0s) and solution (e.g. 4545 4). For flip v1, any of the solutions will work, so test locally first before testing at the remote to get the flag.

`TetCTF{fr0m_0n3_b1t_fl1pp3d_t0_full_k3y_r3c0v3ry}`

The only difference with flip v2 is that you can't flip a bit in main.
```
OFFSET_MAIN_START = 0x1169 # 4457

OFFSET_MAIN_END = 0x11ed # 4589
```
That means we can't use one of the first two solutions we found. Good thing we found more than just those.

`TetCTF{fr0m_0n3_b1t_fl1pp3d_t0_full_k3y_r3c0v3ry_d043a7ff4cf6285a}`

Easiest points of my life. Due to weird point scaling, this was worth 10x the other 3 challenges I solved (which were worth the same 100 points as the Welcome challenge).