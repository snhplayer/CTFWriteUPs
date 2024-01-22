We are given a flags.txt file with a large number of strings that look like the flags for the CTF

```
┌──(kali㉿kali)-[~/Desktop/tampered]
└─$ head flags.txt                                
MAPNA{X9JMN#CO4W1YrE%8%!ULanDXl$Yy=H>PLe5pJ*pk}
MAPNA{m+0ORa'p2TIqjBH3On+SbjjG1w*?p&hWMlW8D[cU}
MAPNA{6;,//u%ED<<K)Vlq</NCcsgM?nwdKwE8O4p?/>wq}
MAPNA{H9q(/3oNRmp4I(UZ9GIf'4*=Nz&60dkUJ?ymR7M@}
MAPNA{EprAuVKi\v<'.ACK>ier"Fgs(5o3)ZdUTdI7K66@}
MAPNA{lQE?RV0s7tuz6s3IQCx=E"i,YCxo;/N%uS=WpQ.L}
MAPNA{AfHAr6L++57S3;8hQTfO9,ppVoNn*VRxh(8Y3QM\}
MAPNA{.Rb3,:d2JJ4Sii%C9>lmGWA8O+Oni%zl3bS6I):v}
MAPNA{Ps?u1UgN+[d-d.V(pgXOiP6Z%gX(tq)2m=4K,e/t}
MAPNA{pB($5JY\jhj'1G??DtxsAAxQeg!y7&llu&[O2wqg}

┌──(kali㉿kali)-[~/Desktop/tampered]
└─$ cat flags.txt | wc -l
31337
```

That's a lot of flags and more than we could manually scroll through to try and spot any differences. One idea is to count the number of characters in each flag and see if there are any differences

```
┌──(kali㉿kali)-[~/Desktop/tampered]
└─$ cat flags.txt | awk '{print length}' | uniq -c
   9790 49
      1 48
      1 50
  21545 49
```

Looks like either the 48 or 50 length flags might be what we are looking for

```
┌──(kali㉿kali)-[~/Desktop/tampered]
└─$ cat flags.txt | awk 'length($0) == 48'     
MAPNA{Tx,D51otN\eUf7qQ7>ToSYQ\;5P6jTIHH#6TL+uv}
                                                                                                                           
┌──(kali㉿kali)-[~/Desktop/tampered]
└─$ cat flags.txt | awk 'length($0) == 50'
MAPNA{R6Z@//\>caZ%%k)=ci3$IyOkSGK%w<"V7kgesY&k}
```

If we try both flags the flag with length 48 is the valid one

>MAPNA{Tx,D51otN\eUf7qQ7>ToSYQ\;5P6jTIHH#6TL+uv}