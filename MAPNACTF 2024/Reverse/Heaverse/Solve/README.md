Run Heaverse with gdb (I have pwndbg set up), ctrl-c when a beep is played, see this:
![alt text](https://158212888-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2Fpfs5GbEFUvNmvw1Ekwmu%2Fuploads%2F976UpWABkxHpCp318Yiw%2Fimage.png?alt=media&token=0e3ac6e1-50fe-4e07-ab6b-136dd3e08484)

We see morse code in RBX, when continuing and ctrl+c, we see the morse passed in is slowly iterated. Therefore we just need to print out the memory at that location to see the full string. Printing at an address slightly above we get:

![alt text](https://158212888-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2Fpfs5GbEFUvNmvw1Ekwmu%2Fuploads%2FxBpN73QnMWYHxUOEHTKx%2Fimage.png?alt=media&token=2fbbe5e9-fec4-49f4-b33d-c311fbb7a254)

Copy paste into cyberchef to decode the morse, and you get JUS7LIST3NN0TREV3RSE but it doesn't work directly, follow the instructions in the description to get:

MAPNA{JUS7_LIST3N_N0T_REV3RSE}
