Tetim: The secret.enc png rgb values was the ascii values of the flag.

```
from PIL import Image

img = Image.open("secret.enc")

width, height = img.size

flag = ""

for y in range(height):
    for x in range(width):
        r, g, b = img.getpixel((x, y))
        flag += chr(g)

print(flag)
```