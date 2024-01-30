
### 

TET & 4N6 (52 solves)

#### 
```
Description:

-   Author: Stirring
    

-   Tet is coming, TetCTF is coming again. Like every year, I continued to register to play CTF, read the rules to prepare for the competition. After reading the rules, my computer seemed unusual, it seemed like it was infected with malicious code somewhere. Can you find out?
    

-   1. Find the malicious code and tell me the IP and Port C2
    

-   2. What was the first flag you found?
    

-   3. After registering an account, I no longer remember anything about my account. 

Can you help me find and get the second flag?
    

Format : TetCTF{IP:Port_Flag1_Flag2}

Ex: TetCTF{1.1.1.1:1234_Hello_HappyForensics}
```
#### 

Solution:[](#solution-2)

The hardest 100 points welcome-equivalent solve of my life.

We're given a raw dump (TETCTF-2024-20240126-203010.raw) that's 5.4 GB (!!!), and a Backup.ad1 file that's 222 MB and need to find the malicious code and then something about their account.

Some grep-fu:
```
# Useful grep flags:

-r: Recursive match

-i: Match case insenitive

-n: Print line number for match

-a: Print match even for binaries

-o: Print only the match

-C <n>: Provide n lines of context above/below match

-E (or egrep): Regex matching
```
We can combine this with file redirection to get binary snippets put in a file to explore with your method of choice (vim/hex editor/strings/cat/etc.). An example: grep -ia -C 10 tetctf TET*.raw > tetctfmatch.bin. We can then `strings tetctfmatch.bin | less` to get a quick idea if we want to explore further, and can open the file to see all the hex or cat it to a file to strip out all the non-printable binary characters (since sometimes text is obfuscated with nulls in between each character so it won't be listed in strings).

After an hour or two of this, it'll be clear that the raw file captures the process of accessing and registering at the tetctf website, doing google searches, and various accesses to pastebin and downloads. There's a dummy pastebin link scattered in the binary that is just a placeholder flag, and another pastebin link that is locked. However, with enough analysis of how web traffic is saved in the binary, it's clear that pastebin contents are saved with the following postfix: `- Pastebin.com`

There are many pastebins in the raw file (seemingly just from general web browsing), but that prefix always follows when it's in relation to a capture of the actual content on the page. Doing a grep for that will show many instances of the second part of the flag.

`Flag 2: R3c0v3rry_34sy_R1ght? - Pastebin.com`

Comparatively the first part of the challenge is a lot less straight-forward. There is a suspicious zip file that's listed many times in the raw file: `https://www.file.io/GN6v/download/eKHCxsHdpFZc`. This file is seen to be a zip file that was later extracted, and is related to the part in the description regarding being infected after reading the rules. Some other interesting snippets in the raw:
```
misc #3TetCTF2024-Rules.LNK
C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE/nC:\Users\Stirring\Downloads\TetCTF2024-Rules.docx
# And a ton of red herrings such as google searches, ommitted
```
A rough idea can be gathered from this, where a malicious word document was downloaded and run. From here, there's no way around it but to go back to the ad1 file that seemed relatively useless with the same methods. Basically, the files in it can be extracted if you download FTK Imager (link: https://www.exterro.com/ftk-imager). They ask for a ton of info for the download (which isn't verified aside from email format), and it's only compatible with Windows, two things that stopped me from doing this for a few hours.

Once you install it, you can add the .ad1 and then right click one of the top level entries to extract all the files. I extracted them to a shared folder that I use between all my VMs.

At this point, things were a bit of a blur and I went in circles, (a red herring minikatz direction, various system logs, etc.), but knew the end goal was to find something related to a malicious word file. I eventually stumbled upon the Word template files, which included `./Roaming/Microsoft/Templates/normal/word/vbaProject.bin`. I may have needed to unzip a doc to see it, don't remember for sure.

There are some IP addresses and ports in there which seems weird, and looking at the output of strings on the file, there is a suspicious base64 string: `Vmxjd2VFNUhSa2RqUkZwVFZrWndTMVZ0ZUhkU1JsWlhWRmhvVldGNlZrbFdSM2hQVkd4R1ZVMUVhejA9`. Putting it in cyberchef to base64 decode it, it seems like garbage, but don't give up.

![](https://158212888-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2Fpfs5GbEFUvNmvw1Ekwmu%2Fuploads%2FW1vIJE2ADiPd6q2qGTaQ%2Fimage.png?alt=media&token=815d9288-8d58-4168-a910-b964524a8159)

5 layers of base64

We now have the flag!

`TetCTF{172.20.25.15:4444_VBA-M4cR0_R3c0v3rry_34sy_R1ght?}`